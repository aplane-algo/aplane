// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagetable

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

var (
	testSelector = types.Address{0xA1, 0x02, 0x03}
	testGenesis  = func() []byte {
		g := make([]byte, 32)
		for i := range g {
			g[i] = byte(0x40 + i)
		}
		return g
	}()
)

func stageAddr(i uint64) types.Address {
	var a types.Address
	binary.BigEndian.PutUint64(a[:8], i+1)
	a[31] = 0x7f
	return a
}

func stageAddrs(from, to uint64) []types.Address {
	out := make([]types.Address, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, stageAddr(i))
	}
	return out
}

func openTest(t *testing.T, dir string) *Table {
	t.Helper()
	tb, err := Open(filepath.Join(dir, "a.stages"), testSelector, testGenesis)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return tb
}

func TestEmptyTableWhenFileMissing(t *testing.T) {
	tb := openTest(t, t.TempDir())
	if tb.Len() != 0 {
		t.Fatalf("Len = %d, want 0", tb.Len())
	}
	if _, ok := tb.Lookup(stageAddr(0)); ok {
		t.Fatal("empty table resolved an address")
	}
	if _, ok := tb.Address(0); ok {
		t.Fatal("empty table returned an address")
	}
	if _, err := os.Stat(tb.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open created a file without any append")
	}
}

func TestAppendPersistsAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	tb := openTest(t, dir)
	if err := tb.Append(stageAddrs(0, 5)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Append(stageAddrs(5, 7)); err != nil {
		t.Fatal(err)
	}
	if tb.Len() != 7 {
		t.Fatalf("Len = %d, want 7", tb.Len())
	}
	for i := uint64(0); i < 7; i++ {
		if stage, ok := tb.Lookup(stageAddr(i)); !ok || stage != i {
			t.Fatalf("Lookup(stage %d) = %d, %v", i, stage, ok)
		}
		if a, ok := tb.Address(i); !ok || a != stageAddr(i) {
			t.Fatalf("Address(%d) wrong", i)
		}
	}

	reopened := openTest(t, dir)
	if reopened.Len() != 7 {
		t.Fatalf("reopened Len = %d, want 7", reopened.Len())
	}
	if stage, ok := reopened.Lookup(stageAddr(6)); !ok || stage != 6 {
		t.Fatalf("reopened Lookup = %d, %v", stage, ok)
	}
	if info, err := os.Stat(tb.Path()); err != nil || info.Size() != int64(headerSize+7*addressSize+checksumSize) {
		t.Fatalf("file size = %v, %v", info, err)
	}
}

func TestAppendRejectsDuplicateAndNoop(t *testing.T) {
	tb := openTest(t, t.TempDir())
	if err := tb.Append(nil); err != nil {
		t.Fatalf("empty append: %v", err)
	}
	if err := tb.Append(stageAddrs(0, 3)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Append([]types.Address{stageAddr(1)}); err == nil {
		t.Fatal("duplicate address accepted")
	}
	if tb.Len() != 3 {
		t.Fatalf("failed append changed Len to %d", tb.Len())
	}
}

func corruptAndReopen(t *testing.T, mutate func(data []byte) []byte) (*Table, error) {
	t.Helper()
	dir := t.TempDir()
	tb := openTest(t, dir)
	if err := tb.Append(stageAddrs(0, 4)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tb.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tb.Path(), mutate(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return Open(tb.Path(), testSelector, testGenesis)
}

func withChecksum(body []byte) []byte {
	sum := sha256.Sum256(body)
	return append(body, sum[:]...)
}

func TestCorruptTableIsDiscardedAndStartsEmpty(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"flipped bit": func(d []byte) []byte { d[headerSize+3] ^= 0x01; return d },
		"truncated":   func(d []byte) []byte { return d[:len(d)-5] },
		"garbage":     func([]byte) []byte { return []byte("not a table") },
		"wrong account, valid checksum": func(d []byte) []byte {
			body := d[:len(d)-checksumSize]
			body[len(magic)+2] ^= 0xff
			return withChecksum(body)
		},
		"wrong network, valid checksum": func(d []byte) []byte {
			body := d[:len(d)-checksumSize]
			body[len(magic)+2+32] ^= 0xff
			return withChecksum(body)
		},
		"remapped stage, valid checksum": func(d []byte) []byte {
			// Swap stages 1 and 2: the count and checksum stay consistent, so
			// only a derivation can catch this. Open accepts it; the design
			// relies on signing never trusting the table.
			body := d[:len(d)-checksumSize]
			a, b := headerSize+1*addressSize, headerSize+2*addressSize
			tmp := append([]byte(nil), body[a:a+addressSize]...)
			copy(body[a:], body[b:b+addressSize])
			copy(body[b:], tmp)
			return withChecksum(body)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tb, err := Open("", testSelector, testGenesis)
			_ = tb
			_ = err
			tb, err = corruptAndReopen(t, mutate)
			if name == "remapped stage, valid checksum" {
				if err != nil || tb.Len() != 4 {
					t.Fatalf("remapped table should load (err %v, len %d)", err, tb.Len())
				}
				if stage, _ := tb.Lookup(stageAddr(1)); stage != 2 {
					t.Fatalf("remapped lookup = %d, want the remapped 2", stage)
				}
				return
			}
			if !errors.Is(err, ErrDiscarded) {
				t.Fatalf("err = %v, want ErrDiscarded", err)
			}
			if tb == nil || tb.Len() != 0 {
				t.Fatalf("discarded table not empty: %v", tb)
			}
			if _, statErr := os.Stat(tb.Path()); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("unusable file was not removed")
			}
			// The empty table is usable again.
			if err := tb.Append(stageAddrs(0, 2)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenRejectsBadGenesisLength(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "x.stages"), testSelector, []byte{1, 2}); err == nil {
		t.Fatal("short genesis accepted")
	}
}

func TestConcurrentAppendsSerialize(t *testing.T) {
	dir := t.TempDir()
	tb := openTest(t, dir)
	const workers, each = 8, 16
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// Distinct addresses per worker; order of stages is whatever
				// the lock decides, and the table must stay prefix-complete.
				var a types.Address
				a[0], a[1], a[31] = byte(w), byte(i), 0x55
				if err := tb.Append([]types.Address{a}); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if tb.Len() != workers*each {
		t.Fatalf("Len = %d, want %d", tb.Len(), workers*each)
	}
	reopened := openTest(t, dir)
	if reopened.Len() != workers*each {
		t.Fatalf("reopened Len = %d", reopened.Len())
	}
	for i := uint64(0); i < reopened.Len(); i++ {
		a, _ := reopened.Address(i)
		if stage, ok := reopened.Lookup(a); !ok || stage != i {
			t.Fatalf("index inconsistent at %d", i)
		}
	}
}

func TestStoreCachesAndDeletes(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	store := NewStore(paths)
	tb, err := store.Table(testSelector, testGenesis)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.Table(testSelector, testGenesis)
	if err != nil || again != tb {
		t.Fatalf("store returned a different table (%v)", err)
	}
	if err := tb.Append(stageAddrs(0, 2)); err != nil {
		t.Fatal(err)
	}
	if tb.Path() != paths.StageTablePath(testSelector.String()) {
		t.Fatalf("table path %q", tb.Path())
	}
	if err := store.Delete(testSelector.String()); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(tb.Path()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("Delete left the file")
	}
	fresh, err := store.Table(testSelector, testGenesis)
	if err != nil || fresh == tb || fresh.Len() != 0 {
		t.Fatalf("table after delete: %v, same=%v, len=%d", err, fresh == tb, fresh.Len())
	}
	if err := store.Delete(testSelector.String()); err != nil {
		t.Fatalf("deleting a missing table: %v", err)
	}
	if err := store.Delete("not-a-selector"); err == nil {
		t.Fatal("unsafe selector accepted")
	}
}

func TestStoreReportsDiscardedTableOnce(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	path := paths.StageTablePath(testSelector.String())
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(paths)
	tb, err := store.Table(testSelector, testGenesis)
	if !errors.Is(err, ErrDiscarded) || tb == nil {
		t.Fatalf("first open: %v, %v", tb, err)
	}
	if _, err := store.Table(testSelector, testGenesis); err != nil {
		t.Fatalf("second open reported again: %v", err)
	}
}
