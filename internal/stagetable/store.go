// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagetable

import (
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
func (s *Store) Table(selector types.Address, genesisHash []byte, present func() bool) (*Table, error) {
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
		return t, nil
	}
	t, err := Open(s.paths.StageTablePath(key), selector, genesisHash)
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
	}
	if err := fsutil.RemoveDurable(s.paths.StageTablePath(selector)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stage table: %w", err)
	}
	return nil
}
