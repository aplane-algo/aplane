// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"os"
	"testing"
)

// A cache with no client data directory lives in memory: it never writes a
// cache file or key into the working directory.
func TestCacheWithoutDataDirWritesNothing(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	if store := NewStore(""); store != nil {
		t.Fatalf("NewStore(\"\") = %#v, want no store", store)
	}
	cache := NewAuthAddressCacheForStore(nil)
	if err := cache.UpdateAuthAddress("ADDR1", "AUTH1", "testnet"); err != nil {
		t.Fatalf("UpdateAuthAddress() error = %v", err)
	}
	if got, _ := cache.GetAuthAddress("ADDR1"); got != "AUTH1" {
		t.Fatalf("in-memory auth address = %q, want AUTH1", got)
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("working directory gained %d entries; first %q", len(entries), entries[0].Name())
	}
}
