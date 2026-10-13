// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stagetable keeps a rotating account's stage address table: the
// addresses A_0 … A_{k-1} of its first k stages, derived from the account's
// seed and cached on disk so that finding the stage behind an authorizer is a
// lookup instead of a derivation per stage.
//
// The table is never trusted. Every address it returns is a hint that the
// signing derivation confirms (the program signed with must derive to the
// authorizer), so a tampered or corrupt table costs a refusal or a rebuild,
// never a wrong signature. It holds no secrets: stage addresses are hashes,
// and only the live stage's program can rekey the account.
//
// A table is prefix-complete. Its length is the next stage to derive, which
// is what lets a scan resume after a restart or a request deadline.
package stagetable

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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

	mu     sync.RWMutex
	addrs  []types.Address
	index  map[types.Address]uint64
	closed bool
}

// Open loads the table at path for the account with selector on the network
// with genesisHash, creating an empty table when the file does not exist.
//
// A file that is unreadable, corrupt, or belongs to another account or
// network is removed and the table starts empty; Open then returns the table
// together with an error wrapping ErrDiscarded that says why, so the caller
// can log it and continue. Any other error means the table is unusable.
func Open(path string, selector types.Address, genesisHash []byte) (*Table, error) {
	if len(genesisHash) != 32 {
		return nil, fmt.Errorf("stage table genesis hash must be 32 bytes, got %d", len(genesisHash))
	}
	t := &Table{path: path, selector: selector, index: make(map[types.Address]uint64)}
	copy(t.genesis[:], genesisHash)

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read stage table: %w", err)
	}
	addrs, decodeErr := decode(data, selector, t.genesis)
	if decodeErr != nil {
		if rmErr := fsutil.RemoveDurable(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove unusable stage table: %w (after: %v)", rmErr, decodeErr)
		}
		return t, fmt.Errorf("%w: %v", ErrDiscarded, decodeErr)
	}
	t.addrs = addrs
	for i, a := range addrs {
		t.index[a] = uint64(i)
	}
	return t, nil
}

// Path is the table's file.
func (t *Table) Path() string { return t.path }

// Len is the number of stages the table covers: stages 0 … Len()-1.
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
	if stage >= uint64(len(t.addrs)) {
		return types.Address{}, false
	}
	return t.addrs[stage], true
}

// Append adds the addresses of stages Len() … Len()+len(addrs)-1 and
// publishes the whole table durably before returning. A failed write leaves
// both the file and the in-memory table unchanged.
func (t *Table) Append(addrs []types.Address) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.appendLocked(uint64(len(t.addrs)), addrs)
}

// AppendFrom adds the addresses of stages start … start+len(addrs)-1. Stages
// the table already covers must match and are skipped, so two fills that
// derived the same range concurrently both succeed; a mismatch is an error,
// since two derivations of one stage can only differ if something is wrong.
// start may not exceed Len(), because the table never has gaps.
func (t *Table) AppendFrom(start uint64, addrs []types.Address) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	have := uint64(len(t.addrs))
	if start > have {
		return fmt.Errorf("stage table covers %d stages; cannot append from %d", have, start)
	}
	for start < have && len(addrs) > 0 {
		if t.addrs[start] != addrs[0] {
			return fmt.Errorf("stage %d derived to %s but the table holds %s", start, addrs[0], t.addrs[start])
		}
		start++
		addrs = addrs[1:]
	}
	return t.appendLocked(start, addrs)
}

func (t *Table) appendLocked(start uint64, addrs []types.Address) error {
	if t.closed {
		return ErrClosed
	}
	if len(addrs) == 0 {
		return nil
	}
	if start != uint64(len(t.addrs)) {
		return fmt.Errorf("stage table covers %d stages; cannot append from %d", len(t.addrs), start)
	}
	for _, a := range addrs {
		if _, dup := t.index[a]; dup {
			return fmt.Errorf("stage address %s already present in the table", a)
		}
	}
	next := make([]types.Address, 0, len(t.addrs)+len(addrs))
	next = append(next, t.addrs...)
	next = append(next, addrs...)
	if err := fsutil.MkdirAllPrivate(filepath.Dir(t.path)); err != nil {
		return fmt.Errorf("create stage table directory: %w", err)
	}
	if err := fsutil.WriteFileDurable(t.path, encode(t.selector, t.genesis, next)); err != nil {
		return fmt.Errorf("write stage table: %w", err)
	}
	base := uint64(len(t.addrs))
	for i, a := range addrs {
		t.index[a] = base + uint64(i)
	}
	t.addrs = next
	return nil
}

// close marks the table deleted: every later append fails with ErrClosed, so
// a fill still holding this handle cannot recreate the file. It waits for an
// in-flight append to finish first.
func (t *Table) close() {
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
