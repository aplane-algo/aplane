// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagetable

import (
	"errors"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSparseRestartAndHintRecency(t *testing.T) {
	dir := t.TempDir()
	tb := openTest(t, dir)
	if err := tb.AppendFrom(50000, stageAddrs(50000, 50003)); err != nil {
		t.Fatal(err)
	}
	round := uint64(100)
	local := Hint{Stage: 50000, Round: &round, Source: "local_observation", Authorizer: stageAddr(50000)}
	if err := tb.SetHint(local); err != nil {
		t.Fatal(err)
	}
	for _, h := range []Hint{
		{Stage: 90000, Source: "backup"},
		{Stage: 90000, Round: &round, Source: "backup"},
		{Stage: 90000, Round: &round, Source: "local_observation"},
	} {
		if err := tb.SetHint(h); err != nil {
			t.Fatal(err)
		}
	}
	tb = openTest(t, dir)
	if tb.Len() != 3 || tb.FirstMissing(0) != 0 || tb.FirstMissing(50000) != 50003 {
		t.Fatal("sparse coverage lost")
	}
	if h := tb.RecoveryHint(); h == nil || h.Stage != 50000 || h.Round == nil || *h.Round != 100 {
		t.Fatalf("hint: %+v", h)
	}
	if tb.Verified(50000, stageAddr(50000)) {
		t.Fatal("loaded address trusted without derivation")
	}
	if n := tb.NextCandidate(); n != 50003 {
		t.Fatalf("forward search restarted at %d", n)
	}
	newer := uint64(101)
	if err := tb.SetHint(Hint{Stage: 12, Round: &newer, Source: "backup"}); err != nil {
		t.Fatal(err)
	}
	if tb.RecoveryHint().Stage != 12 {
		t.Fatal("ranked hints by stage instead of round")
	}
}

func TestSparseSearchDoesNotStarveLowerGaps(t *testing.T) {
	dir := t.TempDir()
	tb := openTest(t, dir)
	if err := tb.SetHint(Hint{Stage: 50000, Source: "backup"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		// Four-stage passes, with a restart after the initial forward interval.
		if i == 16 {
			tb = openTest(t, dir)
		}
		n := tb.NextCandidate()
		if err := tb.AppendFrom(n, stageAddrs(n, n+1)); err != nil {
			t.Fatal(err)
		}
	}
	if tb.FirstMissing(0) != 4 {
		t.Fatalf("lower stream progress: %d", tb.FirstMissing(0))
	}
	if tb.FirstMissing(50000) != 50028 {
		t.Fatal("forward progress lost")
	}
}

func TestRepairPreservesIndependentEntriesAndBothIndexes(t *testing.T) {
	tb := openTest(t, t.TempDir())
	if err := tb.AppendFrom(50000, stageAddrs(50000, 50003)); err != nil {
		t.Fatal(err)
	}
	// Wrong mapping at another index for the actual address of stage 8.
	if err := tb.AppendFrom(7, stageAddrs(8, 9)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Repair(8, stageAddr(8)); err != nil {
		t.Fatal(err)
	}
	if _, ok := tb.Address(7); ok {
		t.Fatal("stale forward mapping retained")
	}
	if n, ok := tb.Lookup(stageAddr(8)); !ok || n != 8 {
		t.Fatal("reverse index not repaired")
	}
	if !tb.Verified(50000, stageAddr(50000)) || tb.Len() != 4 {
		t.Fatal("independent verified entries discarded")
	}
}

func TestPersistenceFailureRetainsWorkAndCanRetry(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "parent")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	tb, err := Open(filepath.Join(dir, "cache"), testSelector, testGenesis)
	if err != nil {
		t.Fatal(err)
	}
	tb.path = filepath.Join(blocker, "cache")
	if err := tb.Repair(50000, stageAddr(50000)); !errors.Is(err, ErrPersistence) {
		t.Fatalf("write error: %v", err)
	}
	if !tb.Verified(50000, stageAddr(50000)) || tb.PersistenceError() == nil {
		t.Fatal("lost in-memory derivation")
	}
	tb.path = filepath.Join(dir, "cache")
	if err := tb.Flush(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(tb.path, testSelector, testGenesis)
	if err != nil || reopened.Len() != 1 {
		t.Fatalf("retry did not persist: %v", err)
	}
	tb.close()
	if err := tb.Flush(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed flush accepted")
	}
}

func TestSparseOverflowAndLegacyRead(t *testing.T) {
	tb := openTest(t, t.TempDir())
	if err := tb.AppendFrom(math.MaxUint64, stageAddrs(0, 1)); err == nil {
		t.Fatal("overflow accepted")
	}
	var genesis [32]byte
	copy(genesis[:], testGenesis)
	data := encode(testSelector, genesis, stageAddrs(0, 3))
	if err := os.WriteFile(tb.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(tb.path, testSelector, testGenesis, "test-family")
	if err != nil || reopened.Len() != 3 {
		t.Fatalf("legacy read: %v", err)
	}
	if err := reopened.Repair(50000, stageAddr(50000)); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(tb.path, testSelector, testGenesis, "test-family")
	if err != nil || migrated.Len() != 4 {
		t.Fatalf("migration: %v", err)
	}
	if _, err := Open(tb.path, testSelector, testGenesis, "different-family"); !errors.Is(err, ErrDiscarded) {
		t.Fatal("wrong family accepted")
	}
}

func TestSlowPublicationDoesNotBlockMemoryAndPreservesNewerWork(t *testing.T) {
	dir := t.TempDir()
	tb := openTest(t, dir)
	if err := tb.RecordDerived(50000, stageAddrs(50000, 50001)); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once, unblock sync.Once
	ended := make(chan struct{})
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == dir {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	t.Cleanup(func() { unblock.Do(func() { close(release) }); <-ended; fsutil.TestHook = nil })
	go func() { defer close(ended); done <- tb.Flush() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not reach hook")
	}
	memory := make(chan error, 1)
	go func() {
		if _, ok := tb.Address(50000); !ok {
			memory <- errors.New("missing entry")
			return
		}
		memory <- tb.RecordDerived(50001, stageAddrs(50001, 50002))
	}()
	select {
	case err := <-memory:
		if err != nil {
			unblock.Do(func() { close(release) })
			<-done
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		unblock.Do(func() { close(release) })
		<-done
		t.Fatal("memory waited for cache I/O")
	}
	unblock.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := tb.Flush(); err != nil {
		t.Fatal(err)
	}
	reopened := openTest(t, dir)
	if reopened.Len() != 2 {
		t.Fatalf("old snapshot erased newer work: %d entries", reopened.Len())
	}
}
