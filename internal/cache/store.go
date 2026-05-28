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

// NewStore creates a cache store rooted under <dataDir>/cache.
// If dataDir is empty, it falls back to the legacy relative "cache" directory.
func NewStore(dataDir string) *Store {
	baseDir := "cache"
	if dataDir != "" {
		baseDir = filepath.Join(dataDir, "cache")
	}
	return &Store{baseDir: baseDir, dataDir: dataDir}
}

// NewStoreForCacheDir creates a cache store rooted at an explicit cache
// directory. It does not bind the store to APCLIENT_DATA locking.
func NewStoreForCacheDir(cacheDir string) *Store {
	return &Store{baseDir: cacheDir}
}

func (s *Store) path(filename string) string {
	if s == nil {
		return NewStore("").path(filename)
	}
	return filepath.Join(s.baseDir, filename)
}

func (s *Store) dir() string {
	if s == nil {
		return NewStore("").dir()
	}
	return s.baseDir
}

func (s *Store) clientDataDir() string {
	if s == nil {
		return ""
	}
	return s.dataDir
}
