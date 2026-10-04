// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import "path/filepath"

// Store owns a cache filesystem root.
// It replaces the old process-global mutable cache base directory.
type Store struct {
	baseDir string
	dataDir string
}

// NewStore creates a cache store rooted under <dataDir>/cache. An empty
// dataDir has no store: caches then live in memory only and are never written
// to the working directory.
func NewStore(dataDir string) *Store {
	if dataDir == "" {
		return nil
	}
	return &Store{baseDir: filepath.Join(dataDir, "cache"), dataDir: dataDir}
}

// persistent reports whether the store has a directory to read and write.
func (s *Store) persistent() bool {
	return s != nil && s.baseDir != ""
}

// NewStoreForCacheDir creates a cache store rooted at an explicit cache
// directory. It does not bind the store to APCLIENT_DATA locking.
func NewStoreForCacheDir(cacheDir string) *Store {
	return &Store{baseDir: cacheDir}
}

func (s *Store) path(filename string) string {
	if !s.persistent() {
		return ""
	}
	return filepath.Join(s.baseDir, filename)
}

func (s *Store) dir() string {
	if !s.persistent() {
		return ""
	}
	return s.baseDir
}

func (s *Store) clientDataDir() string {
	if s == nil {
		return ""
	}
	return s.dataDir
}
