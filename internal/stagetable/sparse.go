// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagetable

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const maxCacheBytes = 64 << 20

// Hint is an untrusted recovery candidate, never signing authority. A nil
// Round differs from round zero. Imported observations have Source backup.
type Hint struct {
	Stage      uint64        `json:"stage"`
	Round      *uint64       `json:"observed_round,omitempty"`
	Authorizer types.Address `json:"authorizer"`
	Source     string        `json:"source"`
}

func cloneHint(h *Hint) *Hint {
	if h == nil {
		return nil
	}
	out := *h
	if h.Round != nil {
		r := *h.Round
		out.Round = &r
	}
	return &out
}

// RecoveryHint returns a copy, so callers cannot mutate cache state.
func (t *Table) RecoveryHint() *Hint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return cloneHint(t.hint)
}

// SetHint keeps the newest observation by round, preferring local on ties.
// The caller must verify local observations against the seed and chain first.
func (t *Table) SetHint(h Hint) error {
	if err := t.RecordHint(h); err != nil {
		return err
	}
	return t.Flush()
}

// RecordHint stages an observation for the worker's next publication. It does
// not wait for disk I/O; this keeps foreground signing independent of the cache.
func (t *Table) RecordHint(h Hint) error {
	if h.Stage >= math.MaxUint64-1 || (h.Source != "local_observation" && h.Source != "backup") {
		return errors.New("invalid recovery hint")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrClosed
	}
	old := t.hint
	if old != nil && h.Source == old.Source && h.Stage == old.Stage && h.Authorizer == old.Authorizer {
		// The same observation seen again. A later round is kept in memory for
		// backup snapshots, but it is not a change worth publishing: stages only
		// move forward, so the stored round already orders this hint correctly
		// against any older backup, and rewriting the cache on every pass would
		// turn a steady-state account into a durable write per observation.
		if h.Round != nil && (old.Round == nil || *h.Round > *old.Round) {
			r := *h.Round
			t.hint.Round = &r
		}
		return nil
	}
	newer := old == nil
	if old != nil {
		switch {
		case h.Round != nil && old.Round == nil:
			newer = true
		case h.Round == nil && old.Round != nil:
			newer = false
		case h.Round != nil && *h.Round != *old.Round:
			newer = *h.Round > *old.Round
		default:
			newer = h.Source == "local_observation" && old.Source == "backup"
		}
	}
	if newer {
		t.hint = cloneHint(&h)
		t.searchTurn = 0
		t.dirty = true
		t.revision++
	}
	return nil
}

// NextCandidate gives a bounded initial forward preference, then three forward
// probes for each lower-gap probe. Coverage is durable; scheduling phase is not.
func (t *Table) NextCandidate(anchors ...uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	low := t.firstMissingLocked(0)
	var h uint64
	if t.hint != nil {
		h = t.hint.Stage
	} else if len(anchors) > 0 {
		h = anchors[0]
	} else {
		return low
	}
	forward := t.firstMissingLocked(h)
	if forward-h < 16 {
		return forward
	}
	t.searchTurn++
	if low < h && t.searchTurn%4 == 0 {
		return low
	}
	if forward == math.MaxUint64 {
		return low
	}
	return forward
}

func encodeCache(selector types.Address, genesis [32]byte, entries map[uint64]types.Address, hint *Hint, keyType string) ([]byte, error) {
	meta, err := json.Marshal(cacheMetadata{KeyType: keyType, Hint: hint})
	if err != nil {
		return nil, err
	}
	if len(entries) > (maxCacheBytes-headerSize-checksumSize-len(meta))/40 {
		return nil, errors.New("stage cache exceeds size limit")
	}
	buf := append([]byte(magic), 0, 2)
	buf = append(buf, selector[:]...)
	buf = append(buf, genesis[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(entries)))
	stages := make([]uint64, 0, len(entries))
	for n := range entries {
		stages = append(stages, n)
	}
	sort.Slice(stages, func(i, j int) bool { return stages[i] < stages[j] })
	for _, n := range stages {
		buf = binary.BigEndian.AppendUint64(buf, n)
		a := entries[n]
		buf = append(buf, a[:]...)
	}
	buf = append(buf, meta...)
	sum := sha256.Sum256(buf)
	return append(buf, sum[:]...), nil
}

func decodeCache(data []byte, selector types.Address, genesis [32]byte, keyType string) (map[uint64]types.Address, *Hint, error) {
	if len(data) < headerSize+checksumSize || len(data) > maxCacheBytes {
		return nil, nil, errors.New("file too short")
	}
	if binary.BigEndian.Uint16(data[len(magic):]) == 1 {
		old, err := decode(data, selector, genesis)
		if err != nil {
			return nil, nil, err
		}
		out := make(map[uint64]types.Address, len(old))
		for i, a := range old {
			out[uint64(i)] = a
		}
		return out, nil, nil
	}
	body, sum := data[:len(data)-checksumSize], data[len(data)-checksumSize:]
	want := sha256.Sum256(body)
	if !bytes.Equal(sum, want[:]) {
		return nil, nil, errors.New("checksum mismatch")
	}
	if string(body[:len(magic)]) != magic || binary.BigEndian.Uint16(body[len(magic):]) != 2 {
		return nil, nil, errors.New("unsupported stage cache format")
	}
	off := len(magic) + 2
	if !bytes.Equal(body[off:off+32], selector[:]) || !bytes.Equal(body[off+32:off+64], genesis[:]) {
		return nil, nil, errors.New("stage cache identity mismatch")
	}
	off += 64
	count := binary.BigEndian.Uint64(body[off:])
	off += 8
	if count > uint64(len(body)-off)/40 {
		return nil, nil, errors.New("invalid stage cache count")
	}
	entries := make(map[uint64]types.Address, int(count))
	seen := make(map[types.Address]bool, int(count))
	var previous uint64
	for i := uint64(0); i < count; i++ {
		n := binary.BigEndian.Uint64(body[off:])
		off += 8
		var a types.Address
		copy(a[:], body[off:off+32])
		off += 32
		if n == math.MaxUint64 || (i > 0 && n <= previous) || seen[a] {
			return nil, nil, fmt.Errorf("duplicate or invalid stage record %d", n)
		}
		entries[n] = a
		seen[a] = true
		previous = n
	}
	var meta cacheMetadata
	dec := json.NewDecoder(bytes.NewReader(body[off:]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return nil, nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("trailing stage cache metadata")
	}
	hint := meta.Hint
	if keyType != "" && meta.KeyType != keyType {
		return nil, nil, errors.New("stage cache key type mismatch")
	}
	if hint != nil && (hint.Stage >= math.MaxUint64-1 || (hint.Source != "local_observation" && hint.Source != "backup")) {
		return nil, nil, errors.New("invalid recovery hint")
	}
	return entries, hint, nil
}

type cacheMetadata struct {
	KeyType string `json:"key_type"`
	Hint    *Hint  `json:"hint,omitempty"`
}
