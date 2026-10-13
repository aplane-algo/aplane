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
// network with genesisHash, opening it on first use. A discarded on-disk
// table is reported through an error wrapping ErrDiscarded alongside the
// now-empty table; callers log it and continue.
func (s *Store) Table(selector types.Address, genesisHash []byte) (*Table, error) {
	key := selector.String()
	if err := storepaths.ValidateStageSelector(key); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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

// Delete forgets and removes the table of the account with selector. It is
// called when the key is deleted; the table is derivable, so nothing is
// archived. A missing file is not an error.
func (s *Store) Delete(selector string) error {
	if err := storepaths.ValidateStageSelector(selector); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tables, selector)
	if err := fsutil.RemoveDurable(s.paths.StageTablePath(selector)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stage table: %w", err)
	}
	return nil
}
