// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import "path/filepath"

// Store owns the cache directory <dataDir>/cache.
type Store struct {
	dataDir string
}

// NewStore creates a cache store rooted under <dataDir>/cache. An empty
// dataDir has no store: caches then live in memory only and are never written
// to the working directory.
func NewStore(dataDir string) *Store {
	if dataDir == "" {
		return nil
	}
	return &Store{dataDir: dataDir}
}

// persistent reports whether the store has a directory to read and write. A
// nil store, from an empty dataDir, keeps its caches in memory, and so does
// a zero Store, rather than writing under the working directory.
func (s *Store) persistent() bool {
	return s != nil && s.dataDir != ""
}

func (s *Store) path(filename string) string {
	if !s.persistent() {
		return ""
	}
	return filepath.Join(s.dir(), filename)
}

func (s *Store) dir() string {
	if !s.persistent() {
		return ""
	}
	return filepath.Join(s.dataDir, "cache")
}
