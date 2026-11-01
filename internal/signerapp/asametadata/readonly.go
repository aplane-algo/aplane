// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asametadata

import (
	"errors"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
)

// ErrNoSignerDataDir reports a read-only lookup asked for without a signer
// data directory. There is no fallback: an empty path would otherwise resolve
// to a relative cache directory.
var ErrNoSignerDataDir = errors.New("no signer data directory")

// ReadOnlyStore looks up ASA metadata in a signer data directory without
// writing to it. It never creates the cache directory or its key, never
// fetches from algod, and cannot save. A policy authoring tool uses it beside
// a running daemon, which owns the cache and its writes.
type ReadOnlyStore struct {
	cacheStore *cache.Store
}

// NewReadOnlyStore returns a read-only lookup for the signer data directory
// dataDir, which must be named.
func NewReadOnlyStore(dataDir string) (ReadOnlyStore, error) {
	if dataDir == "" {
		return ReadOnlyStore{}, ErrNoSignerDataDir
	}
	return ReadOnlyStore{cacheStore: cache.NewStoreForCacheDir(filepath.Join(dataDir, "cache"))}, nil
}

// MetadataByID returns an asset's metadata and whether it was found. A
// built-in entry is labelled asa.SourceBuiltin and is returned even when the
// signer's cache is unreadable; any other entry comes from the cache and is
// labelled asa.SourceCache. A cache that cannot be read or verified is
// returned as an error alongside whatever was found, so the caller can report
// it rather than treat it as an empty cache.
func (s ReadOnlyStore) MetadataByID(network string, assetID uint64) (asa.Metadata, bool, error) {
	loaded, loadErr := cache.LoadASACacheReadOnly(s.cacheStore, network)
	info, ok := loaded.Assets[assetID]
	if !ok {
		return asa.Metadata{}, false, loadErr
	}
	source := asa.SourceCache
	if _, builtin := cache.BuiltinASAInfo(network, assetID); builtin {
		source = asa.SourceBuiltin
	}
	return metadataFromInfo(network, assetID, info, source), true, loadErr
}
