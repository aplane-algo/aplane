// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stagetable keeps a rotating account's stage address table: the
// addresses at explicitly numbered stages, derived from the account's
// seed and cached on disk so that finding the stage behind an authorizer is a
// lookup instead of a derivation per stage.
//
// The table is never trusted. Every address it returns is a hint that the
// signing derivation confirms (the program signed with must derive to the
// authorizer), so a tampered or corrupt table costs a refusal or a rebuild,
// never a wrong signature. It holds no secrets: stage addresses are hashes,
// and only the live stage's program can rekey the account.
//
// A table is sparse. Explicit stage numbers preserve gaps and discovery progress.
package stagetable

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/aplane-algo/aplane/internal/fsutil"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	magic         = "APSTAGES"
	formatVersion = uint16(1)
	headerSize    = len(magic) + 2 + 32 + 32 + 8
	addressSize   = 32
	checksumSize  = sha256.Size
)

// ErrDiscarded reports that an unreadable or mismatched table file was
// removed and the table started empty.
var ErrDiscarded = errors.New("stage table discarded")

// ErrClosed reports an append to a table whose key has been deleted.
var ErrPersistence = errors.New("stage cache persistence failed")

var ErrClosed = errors.New("stage table closed")

// ErrNoKey reports a request for the table of an account whose key is not
// present, which is how a fill that lost a race with key deletion is kept
// from recreating the table.
var ErrNoKey = errors.New("stage table: key not present")

// Table is one account's stage address table, loaded in memory and mirrored
// durably on disk. Methods are safe for concurrent use.
type Table struct {
	path     string
	selector types.Address
	genesis  [32]byte
	keyType  string

	writeMu    sync.Mutex
	revision   uint64
	mu         sync.RWMutex
	addrs      map[uint64]types.Address
	hint       *Hint
	dirty      bool
	writeErr   error
	searchTurn uint64
	verified   map[uint64]types.Address
	index      map[types.Address]uint64
	closed     bool
}

// Open loads the table at path for the account with selector on the network
// with genesisHash, creating an empty table when the file does not exist.
//
// A file that is unreadable, corrupt, or belongs to another account or
// network is removed and the table starts empty; Open then returns the table
// together with an error wrapping ErrDiscarded that says why, so the caller
// can log it and continue. Any other error means the table is unusable.
func Open(path string, selector types.Address, genesisHash []byte, keyTypes ...string) (*Table, error) {
	if len(genesisHash) != 32 {
		return nil, fmt.Errorf("stage table genesis hash must be 32 bytes, got %d", len(genesisHash))
	}
	t := &Table{path: path, selector: selector, index: make(map[types.Address]uint64), addrs: make(map[uint64]types.Address), verified: make(map[uint64]types.Address)}
	copy(t.genesis[:], genesisHash)
	if len(keyTypes) > 0 {
		t.keyType = keyTypes[0]
	}

	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read stage table: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCacheBytes+1))
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read stage table: %w", err)
	}
	addrs, hint, decodeErr := decodeCache(data, selector, t.genesis, t.keyType)
	if decodeErr != nil {
		if rmErr := fsutil.RemoveDurable(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove unusable stage table: %w (after: %v)", rmErr, decodeErr)
		}
		return t, fmt.Errorf("%w: %v", ErrDiscarded, decodeErr)
	}
	t.addrs = addrs
	t.hint = hint
	for i, a := range addrs {
		t.index[a] = i
	}
	return t, nil
}

// Path is the table's file.
func (t *Table) Path() string { return t.path }

// Len is the number of cached entries, not prefix coverage or a stage index.
func (t *Table) Len() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return uint64(len(t.addrs))
}

// Lookup returns the stage whose address is addr.
func (t *Table) Lookup(addr types.Address) (uint64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	stage, ok := t.index[addr]
	return stage, ok
}

// Address returns the cached address of stage, if the table covers it.
func (t *Table) Address(stage uint64) (types.Address, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	a, ok := t.addrs[stage]
	return a, ok
}

// Append inserts a range at the first gap from zero. Callers with an explicit
// stage must use AppendFrom; entry count has no stage semantics.
func (t *Table) Append(addrs []types.Address) error {
	t.mu.Lock()
	err := t.insertLocked(t.firstMissingLocked(0), addrs, false)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	return t.Flush()
}

// AppendFrom inserts an explicit derived range without filling preceding gaps.
// Conflicting cached values are rejected; Repair replaces a verified mapping.
func (t *Table) AppendFrom(start uint64, addrs []types.Address) error {
	t.mu.Lock()
	err := t.insertLocked(start, addrs, false)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	return t.Flush()
}

func (t *Table) insertLocked(start uint64, addrs []types.Address, repair bool) error {
	if t.closed {
		return ErrClosed
	}
	if uint64(len(addrs)) > math.MaxUint64-start {
		return errors.New("stage range overflows")
	}
	next := maps.Clone(t.addrs)
	index := maps.Clone(t.index)
	for i, a := range addrs {
		n := start + uint64(i)
		if old, ok := next[n]; ok && old != a {
			if !repair {
				return fmt.Errorf("stage %d disagrees with cached address", n)
			}
			delete(index, old)
		}
		if other, ok := index[a]; ok && other != n {
			if !repair {
				return fmt.Errorf("stage address %s already present", a)
			}
			delete(next, other)
		}
		next[n], index[a] = a, n
	}
	if len(addrs) == 0 {
		return nil
	}
	t.addrs, t.index, t.dirty = next, index, true
	t.revision++
	for i, a := range addrs {
		t.verified[start+uint64(i)] = a
	}
	return nil
}

// Repair publishes a freshly derived address, repairing both indexes.
func (t *Table) Repair(stage uint64, address types.Address) error {
	t.mu.Lock()
	err := t.insertLocked(stage, []types.Address{address}, true)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	return t.Flush()
}

// FirstMissing resumes from actual coverage, never the highest cached index.
func (t *Table) FirstMissing(from uint64) uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.firstMissingLocked(from)
}
func (t *Table) firstMissingLocked(from uint64) uint64 {
	for from < math.MaxUint64 {
		if _, ok := t.addrs[from]; !ok {
			break
		}
		from++
	}
	return from
}

// Flush retries a failed cache publication. Verified memory remains usable.
func (t *Table) Flush() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	entries, hint, revision := maps.Clone(t.addrs), cloneHint(t.hint), t.revision
	t.mu.Unlock()
	data, err := encodeCache(t.selector, t.genesis, entries, hint, t.keyType)
	if err == nil {
		err = fsutil.MkdirAllPrivate(filepath.Dir(t.path))
	}
	if err == nil {
		err = fsutil.WriteFileDurable(t.path, data)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeErr = err
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	if t.revision == revision {
		t.dirty = false
	}
	return nil
}

// PersistenceError reports a failed publication without discarding useful work.
func (t *Table) PersistenceError() error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.writeErr
}

// close marks the table deleted: every later append fails with ErrClosed, so
// a fill still holding this handle cannot recreate the file. It waits for an
// in-flight append to finish first.
func (t *Table) close() {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
}

func encode(selector types.Address, genesis [32]byte, addrs []types.Address) []byte {
	buf := make([]byte, 0, headerSize+len(addrs)*addressSize+checksumSize)
	buf = append(buf, magic...)
	buf = binary.BigEndian.AppendUint16(buf, formatVersion)
	buf = append(buf, selector[:]...)
	buf = append(buf, genesis[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(addrs)))
	for _, a := range addrs {
		buf = append(buf, a[:]...)
	}
	sum := sha256.Sum256(buf)
	return append(buf, sum[:]...)
}

func decode(data []byte, selector types.Address, genesis [32]byte) ([]types.Address, error) {
	if len(data) < headerSize+checksumSize {
		return nil, errors.New("file too short")
	}
	body, sum := data[:len(data)-checksumSize], data[len(data)-checksumSize:]
	if want := sha256.Sum256(body); !bytes.Equal(sum, want[:]) {
		return nil, errors.New("checksum mismatch")
	}
	if string(body[:len(magic)]) != magic {
		return nil, errors.New("bad magic")
	}
	off := len(magic)
	if v := binary.BigEndian.Uint16(body[off:]); v != formatVersion {
		return nil, fmt.Errorf("unsupported format version %d", v)
	}
	off += 2
	if !bytes.Equal(body[off:off+32], selector[:]) {
		return nil, errors.New("table belongs to another account")
	}
	off += 32
	if !bytes.Equal(body[off:off+32], genesis[:]) {
		return nil, errors.New("table belongs to another network")
	}
	off += 32
	count := binary.BigEndian.Uint64(body[off:])
	off += 8
	// The file's own length bounds the allocation: a corrupt count that does
	// not match it is rejected before anything is allocated.
	if uint64(len(body)-off)/addressSize != count || uint64(len(body)-off)%addressSize != 0 {
		return nil, errors.New("length does not match stage count")
	}
	addrs := make([]types.Address, count)
	seen := make(map[types.Address]struct{}, count)
	for i := range addrs {
		copy(addrs[i][:], body[off+i*addressSize:])
		if _, dup := seen[addrs[i]]; dup {
			return nil, fmt.Errorf("stage %d repeats an earlier address", i)
		}
		seen[addrs[i]] = struct{}{}
	}
	return addrs, nil
}

// Verified reports a seed-derived mapping established in this process. Loaded
// records are unverified; callers must still compare against a fresh chain read.
func (t *Table) Verified(stage uint64, a types.Address) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v, ok := t.verified[stage]
	cached, present := t.addrs[stage]
	return !t.closed && ok && v == a && present && cached == a
}

// RecordDerived records completed derivations in memory. Call Flush after the
// bounded batch, including on cancellation, to publish its progress.
func (t *Table) RecordDerived(start uint64, addrs []types.Address) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.insertLocked(start, addrs, true)
}
