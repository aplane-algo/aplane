// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// snapshotTree lists every file and directory under root with its size, mode
// and modification time, or "absent" when root does not exist.
func snapshotTree(t *testing.T, root string) string {
	t.Helper()
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return "absent"
	}
	var lines []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		lines = append(lines, fmt.Sprintf("%s %d %v %d", rel, info.Size(), info.Mode(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return fmt.Sprint(lines)
}

// writeTestnetCache writes a signed testnet ASA cache in dir through the
// ordinary, writable path, holding one asset the built-in table lacks and one
// conflicting entry for a built-in asset.
func writeTestnetCache(t *testing.T, dir string) {
	t.Helper()
	store := NewStoreForCacheDir(dir)
	c := LoadASACacheFromStore(store, "testnet")
	c.Assets[999999] = ASAInfo{Name: "Local Token", UnitName: "LTK", Decimals: 3}
	c.Assets[10458941] = ASAInfo{Name: "Wrong", UnitName: "USDC", Decimals: 0}
	if err := c.SaveCache("testnet"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadASACacheReadOnlyCreatesNothing(t *testing.T) {
	for name, setup := range map[string]func(dir string){
		"missing directory": func(string) {},
		"empty directory":   func(dir string) { _ = os.MkdirAll(dir, 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "cache")
			setup(dir)
			before := snapshotTree(t, dir)
			loaded, err := LoadASACacheReadOnly(NewStoreForCacheDir(dir), "testnet")
			if err != nil {
				t.Fatalf("err = %v, want an empty cache", err)
			}
			if _, ok := loaded.Assets[10458941]; !ok {
				t.Fatal("built-in testnet USDC missing")
			}
			if err := loaded.SaveCache("testnet"); err != nil {
				t.Fatal(err)
			}
			if after := snapshotTree(t, dir); after != before {
				t.Fatalf("cache directory changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
	if loaded, err := LoadASACacheReadOnly(nil, "testnet"); err != nil || len(loaded.Assets) == 0 {
		t.Fatalf("no store: %d entries, err %v; want the built-ins", len(loaded.Assets), err)
	}
}

func TestLoadASACacheReadOnlyReadsAndNeverWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	writeTestnetCache(t, dir)
	before := snapshotTree(t, dir)

	loaded, err := LoadASACacheReadOnly(NewStoreForCacheDir(dir), "testnet")
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Assets[999999]; got.UnitName != "LTK" || got.Decimals != 3 {
		t.Fatalf("cached asset = %+v", got)
	}
	if builtin, _ := BuiltinASAInfo("testnet", 10458941); loaded.Assets[10458941] != builtin {
		t.Fatalf("built-in entry = %+v, want %+v", loaded.Assets[10458941], builtin)
	}
	loaded.Assets[1] = ASAInfo{Name: "x"}
	if err := loaded.SaveCache("testnet"); err != nil {
		t.Fatal(err)
	}
	if after := snapshotTree(t, dir); after != before {
		t.Fatalf("cache directory changed:\nbefore %s\nafter  %s", before, after)
	}
}

func TestLoadASACacheReadOnlyReportsAnUnusableCache(t *testing.T) {
	for name, tt := range map[string]struct {
		damage func(t *testing.T, dir string)
		want   error
	}{
		"tampered": {func(t *testing.T, dir string) {
			path := filepath.Join(dir, "testnet_asa_cache.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var signed SignedCache
			if err := json.Unmarshal(raw, &signed); err != nil {
				t.Fatal(err)
			}
			signed.HMAC = strings.Repeat("0", len(signed.HMAC))
			out, _ := json.Marshal(signed)
			if err := os.WriteFile(path, out, 0o600); err != nil {
				t.Fatal(err)
			}
		}, ErrCacheTampered},
		"key missing": {func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, ".cache_key")); err != nil {
				t.Fatal(err)
			}
		}, ErrCacheKeyMissing},
		"not a cache file": {func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "testnet_asa_cache.json"), []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "cache")
			writeTestnetCache(t, dir)
			tt.damage(t, dir)
			before := snapshotTree(t, dir)

			loaded, err := LoadASACacheReadOnly(NewStoreForCacheDir(dir), "testnet")
			if err == nil {
				t.Fatal("an unusable cache loaded without an error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if _, ok := loaded.Assets[999999]; ok {
				t.Fatal("an entry from the unusable cache was returned")
			}
			if _, ok := loaded.Assets[10458941]; !ok {
				t.Fatal("built-in entries missing")
			}
			if after := snapshotTree(t, dir); after != before {
				t.Fatalf("cache directory changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}
