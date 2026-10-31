// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asametadata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
)

// snapshotDataDir lists every path under dir with its size, mode and
// modification time.
func snapshotDataDir(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		lines = append(lines, fmt.Sprintf("%s %d %v %d", rel, info.Size(), info.Mode(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return fmt.Sprint(lines)
}

func TestNewReadOnlyStoreRequiresADataDir(t *testing.T) {
	if _, err := NewReadOnlyStore(""); !errors.Is(err, ErrNoSignerDataDir) {
		t.Fatalf("err = %v, want ErrNoSignerDataDir", err)
	}
}

func TestReadOnlyStoreLabelsSourcesAndWritesNothing(t *testing.T) {
	dataDir := t.TempDir()
	ro, err := NewReadOnlyStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	empty := snapshotDataDir(t, dataDir)

	// A data directory with no cache yet: built-ins only, nothing created.
	meta, ok, err := ro.MetadataByID("testnet", 10458941)
	if err != nil || !ok || meta.Source != asa.SourceBuiltin || meta.Decimals != 6 {
		t.Fatalf("built-in lookup = %+v, %v, %v", meta, ok, err)
	}
	if _, ok, err := ro.MetadataByID("testnet", 999999); ok || err != nil {
		t.Fatalf("unknown asset: found %v, err %v", ok, err)
	}
	if after := snapshotDataDir(t, dataDir); after != empty {
		t.Fatalf("lookup created files:\nbefore %s\nafter  %s", empty, after)
	}

	// The daemon's writable store fills the cache; the read-only store sees it.
	if err := NewStore(dataDir).SaveLocalMetadata("testnet", asa.Metadata{AssetID: 999999, Name: "Local Token", UnitName: "LTK", Decimals: 3}); err != nil {
		t.Fatal(err)
	}
	filled := snapshotDataDir(t, dataDir)
	meta, ok, err = ro.MetadataByID("testnet", 999999)
	if err != nil || !ok || meta.Source != asa.SourceCache || meta.Decimals != 3 || meta.UnitName != "LTK" {
		t.Fatalf("cached lookup = %+v, %v, %v", meta, ok, err)
	}
	if after := snapshotDataDir(t, dataDir); after != filled {
		t.Fatalf("lookup changed the cache:\nbefore %s\nafter  %s", filled, after)
	}
}

func TestReadOnlyStoreReportsACorruptCacheButKeepsBuiltins(t *testing.T) {
	dataDir := t.TempDir()
	if err := NewStore(dataDir).SaveLocalMetadata("testnet", asa.Metadata{AssetID: 999999, Name: "Local Token", UnitName: "LTK", Decimals: 3}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "cache", "testnet_asa_cache.json"), []byte(`{"version":1,"data":"e30=","hmac":"00"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ro, _ := NewReadOnlyStore(dataDir)
	before := snapshotDataDir(t, dataDir)

	meta, ok, err := ro.MetadataByID("testnet", 10458941)
	if !ok || meta.Source != asa.SourceBuiltin || !errors.Is(err, cache.ErrCacheTampered) {
		t.Fatalf("built-in lookup over a tampered cache = %+v, %v, %v; want the built-in and ErrCacheTampered", meta, ok, err)
	}
	if _, ok, err := ro.MetadataByID("testnet", 999999); ok || !errors.Is(err, cache.ErrCacheTampered) {
		t.Fatalf("cached lookup over a tampered cache: found %v, err %v", ok, err)
	}
	if after := snapshotDataDir(t, dataDir); after != before {
		t.Fatalf("lookup changed the data directory:\nbefore %s\nafter  %s", before, after)
	}
}
