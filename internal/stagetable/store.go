// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagetable

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Store is the process's single owner of the stage tables under one product
// store. It opens each account's table once and hands out the same *Table to
// every caller, so appends are serialized by the table's own lock.
type Store struct {
	paths storepaths.Paths

	mu     sync.Mutex
	tables map[string]*Table
	epoch  uint64
}

// NewStore returns the store for paths.
func NewStore(paths storepaths.Paths) *Store {
	return &Store{paths: paths, tables: make(map[string]*Table)}
}

// Table returns the table of the rotating account with selector on the
// network with genesisHash, opening it on first use. present reports whether
// the account's key still exists; it is consulted under the store's lock, so
// a Table call cannot interleave with Delete: either it runs first and gets
// a handle that Delete then closes, or it runs after and is refused with
// ErrNoKey. A nil present skips the check. A discarded on-disk table is
// reported through an error wrapping ErrDiscarded alongside the now-empty
// table; callers log it and continue.
func (s *Store) Table(selector types.Address, genesisHash []byte, present func() bool, keyTypes ...string) (*Table, error) {
	key := selector.String()
	if err := storepaths.ValidateStageSelector(key); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if present != nil && !present() {
		return nil, ErrNoKey
	}
	if t, ok := s.tables[key]; ok {
		if bytes.Equal(t.genesis[:], genesisHash) && (len(keyTypes) == 0 || t.keyType == keyTypes[0]) {
			return t, nil
		}
		t.close()
		delete(s.tables, key)
		s.epoch++
	}
	t, err := Open(s.paths.StageTablePath(key), selector, genesisHash, keyTypes...)
	if t == nil {
		return nil, err
	}
	s.tables[key] = t
	return t, err
}

// Discard closes a table whose contents were found to disagree with the
// seed and, if it is still the store's current table, removes its file so
// the next Table call opens a fresh one that the worker rebuilds from stage
// 0. A stale handle (one the store has already replaced, because another
// caller discarded it first) is only closed: its file now belongs to the
// replacement and must not be deleted out from under it. Unlike Delete this
// is not about the key going away.
func (s *Store) Discard(t *Table) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.close()
	key := t.selector.String()
	cur, ok := s.tables[key]
	if !ok || cur != t {
		return nil
	}
	delete(s.tables, key)
	s.epoch++
	if err := fsutil.RemoveDurable(t.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stage table: %w", err)
	}
	return nil
}

// Path is where the table of the account with selector lives, whether or
// not it exists.
func (s *Store) Path(selector string) string {
	return s.paths.StageTablePath(selector)
}

// Delete forgets and removes the table of the account with selector. It is
// called when the key is deleted; the table is derivable, so nothing is
// archived. An open handle to the table is closed first, so a fill that is
// still running cannot recreate the file afterwards. A missing file is not
// an error.
func (s *Store) Delete(selector string) error {
	if err := storepaths.ValidateStageSelector(selector); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tables[selector]; ok {
		t.close()
		delete(s.tables, selector)
		s.epoch++
	}
	if err := fsutil.RemoveDurable(s.paths.StageTablePath(selector)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stage table: %w", err)
	}
	return nil
}

// Observations snapshots available hints without reading the chain or loading
// credentials. An empty cache simply contributes no recovery hint to a backup.
func (s *Store) Observations() []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Observation
	for _, t := range s.tables {
		if h := t.RecoveryHint(); h != nil {
			out = append(out, Observation{Account: t.selector, Genesis: t.genesis, KeyType: t.keyType, Hint: *h})
		}
	}
	return out
}

type Observation struct {
	Account types.Address
	Genesis [32]byte
	KeyType string
	Hint    Hint
}

// Invalidate ends the current inventory lifetime: it starts a new derivation
// epoch, so no request coalesces onto a job started under the old inventory,
// and it forgets every table's verified memory, so each mapping is derived
// again before it is trusted. A reload must call it before publishing
// replacement credential inventory.
//
// Handles stay open. A table is bound to its selector, which is the stage 0
// address re-derived from the seed when the key is loaded, and to its genesis
// and key type, which Table checks on every call. A reload therefore cannot put
// a different seed behind an open handle, and closing handles would only fail
// in-flight requests and stop recovery grants whose credential did not change.
// Deleting a key (Delete), discarding a table (Discard) and a genesis or key
// type mismatch (Table) still close the handle.
func (s *Store) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch++
	for _, t := range s.tables {
		t.mu.Lock()
		clear(t.verified)
		t.mu.Unlock()
	}
}

// Epoch identifies the current inventory lifetime for derivation jobs.
func (s *Store) Epoch() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.epoch }
