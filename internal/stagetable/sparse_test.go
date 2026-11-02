// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagetable

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestSparseRestartAndHintRecency(t *testing.T) {
	dir := t.TempDir()
	tb := openTest(t, dir)
	if err := put(tb, 50000, stageAddrs(50000, 50003)); err != nil {
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
		if err := put(tb, n, stageAddrs(n, n+1)); err != nil {
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
	if err := put(tb, 50000, stageAddrs(50000, 50003)); err != nil {
		t.Fatal(err)
	}
	// Wrong mapping at another index for the actual address of stage 8.
	if err := put(tb, 7, stageAddrs(8, 9)); err != nil {
		t.Fatal(err)
	}
	if err := put(tb, 8, []types.Address{stageAddr(8)}); err != nil {
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
	if err := put(tb, 50000, []types.Address{stageAddr(50000)}); !errors.Is(err, ErrPersistence) {
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
	if err := put(tb, math.MaxUint64, stageAddrs(0, 1)); err == nil {
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
	if err := put(reopened, 50000, []types.Address{stageAddr(50000)}); err != nil {
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
	if _, err := tb.RecordDerived(50000, stageAddrs(50000, 50001)); err != nil {
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
		_, err := tb.RecordDerived(50001, stageAddrs(50001, 50002))
		memory <- err
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

// A reload ends verified memory and the derivation epoch but must not close
// handles: the selector binds the seed, so in-flight requests and recovery
// grants holding the table keep working and keep the same table identity.
func TestInvalidateKeepsHandlesAndForgetsVerifiedMemory(t *testing.T) {
	store := NewStore(storepaths.NewPaths(t.TempDir()))
	tb, err := store.Table(testSelector, testGenesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tb.RecordDerived(10, stageAddrs(10, 12)); err != nil {
		t.Fatal(err)
	}
	if !tb.Verified(10, stageAddr(10)) {
		t.Fatal("derived entry not verified")
	}
	epoch := store.Epoch()
	store.Invalidate()
	if store.Epoch() == epoch {
		t.Fatal("reload kept the derivation epoch")
	}
	if tb.Verified(10, stageAddr(10)) || tb.Verified(11, stageAddr(11)) {
		t.Fatal("reload kept verified memory")
	}
	if a, ok := tb.Address(11); !ok || a != stageAddr(11) {
		t.Fatal("reload dropped cached progress")
	}
	again, err := store.Table(testSelector, testGenesis, nil)
	if err != nil || again != tb {
		t.Fatalf("reload replaced the handle (%v)", err)
	}
	// The old handle still accepts work, which verifies again.
	if _, err := tb.RecordDerived(12, stageAddrs(12, 13)); err != nil {
		t.Fatalf("in-flight handle closed by reload: %v", err)
	}
	if err := tb.Flush(); err != nil {
		t.Fatalf("in-flight handle cannot publish: %v", err)
	}
	// Deletion still closes it.
	if err := store.Delete(testSelector.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tb.RecordDerived(13, stageAddrs(13, 14)); !errors.Is(err, ErrClosed) {
		t.Fatalf("deleted handle accepted work: %v", err)
	}
}

// Re-deriving entries the cache already holds, or seeing the same stage again
// at a later round, verifies or refreshes memory without needing publication.
func TestUnchangedObservationsDoNotDirtyTheTable(t *testing.T) {
	tb := openTest(t, t.TempDir())
	if changed, err := tb.RecordDerived(50000, stageAddrs(50000, 50002)); err != nil || !changed {
		t.Fatalf("new entries: changed=%v err=%v", changed, err)
	}
	round := uint64(7)
	if err := tb.RecordHint(Hint{Stage: 50000, Round: &round, Authorizer: stageAddr(50000), Source: "local_observation"}); err != nil {
		t.Fatal(err)
	}
	if err := tb.Flush(); err != nil || tb.Dirty() {
		t.Fatalf("flush: %v dirty=%v", err, tb.Dirty())
	}
	if changed, err := tb.RecordDerived(50000, stageAddrs(50000, 50002)); err != nil || changed || tb.Dirty() {
		t.Fatalf("re-derived entries: changed=%v err=%v dirty=%v", changed, err, tb.Dirty())
	}
	later := uint64(9)
	if err := tb.RecordHint(Hint{Stage: 50000, Round: &later, Authorizer: stageAddr(50000), Source: "local_observation"}); err != nil {
		t.Fatal(err)
	}
	if tb.Dirty() {
		t.Fatal("repeat observation dirtied the table")
	}
	if h := tb.RecoveryHint(); h == nil || h.Round == nil || *h.Round != later {
		t.Fatalf("repeat observation round not kept in memory: %+v", h)
	}
	// A moved stage is a real change.
	moved := later + 1
	if err := tb.RecordHint(Hint{Stage: 50001, Round: &moved, Authorizer: stageAddr(50001), Source: "local_observation"}); err != nil {
		t.Fatal(err)
	}
	if !tb.Dirty() {
		t.Fatal("new stage observation not published")
	}
}

// Remembered scan frontiers must not survive a repair that removes coverage.
func TestFirstMissingFrontierForgetsRemovedCoverage(t *testing.T) {
	tb := openTest(t, t.TempDir())
	if _, err := tb.RecordDerived(0, stageAddrs(0, 10)); err != nil {
		t.Fatal(err)
	}
	if got := tb.FirstMissing(0); got != 10 {
		t.Fatalf("FirstMissing = %d, want 10", got)
	}
	// Stage 3's address turns out to be stage 20's: the repair moves it.
	if _, err := tb.RecordDerived(20, []types.Address{stageAddr(3)}); err != nil {
		t.Fatal(err)
	}
	if got := tb.FirstMissing(0); got != 3 {
		t.Fatalf("FirstMissing after repair = %d, want 3", got)
	}
	if got := tb.MissingRun(3, 5); got != 1 {
		t.Fatalf("MissingRun(3) = %d, want 1", got)
	}
	if got := tb.MissingRun(10, 5); got != 5 {
		t.Fatalf("MissingRun(10) = %d, want 5", got)
	}
}

// A range that repeats an address is refused whole, without mutation.
func TestInsertRefusesAddressRepeatedWithinARange(t *testing.T) {
	tb := openTest(t, t.TempDir())
	a := stageAddr(10)
	if _, err := tb.RecordDerived(10, []types.Address{a, a}); err == nil {
		t.Fatal("record accepted a repeated address")
	}
	if tb.Len() != 0 || tb.Dirty() {
		t.Fatalf("refused range changed the table: len=%d dirty=%v", tb.Len(), tb.Dirty())
	}
}

// An empty key type is unbound, never a mismatch: a caller that does not know
// the type must not discard the cache, and an unbound table binds to the first
// real type and publishes it.
func TestEmptyKeyTypeIsUnboundNotAMismatch(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	const kt = "aplane.rotating-test.v1"
	store := NewStore(paths)
	tb, err := store.Table(testSelector, testGenesis, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := put(tb, 50000, stageAddrs(50000, 50002)); err != nil {
		t.Fatal(err)
	}
	round := uint64(3)
	if err := tb.SetHint(Hint{Stage: 50000, Round: &round, Authorizer: stageAddr(50000), Source: "local_observation"}); err != nil {
		t.Fatal(err)
	}
	if len(store.Observations()) != 0 {
		t.Fatal("unbound table contributed a backup hint")
	}
	// The real type arrives: same handle, now bound, nothing discarded.
	bound, err := store.Table(testSelector, testGenesis, nil, kt)
	if err != nil || bound != tb || bound.KeyType() != kt || bound.Len() != 2 {
		t.Fatalf("binding replaced or emptied the table: %v same=%v type=%q len=%d", err, bound == tb, bound.KeyType(), bound.Len())
	}
	if err := bound.Flush(); err != nil {
		t.Fatal(err)
	}
	if obs := store.Observations(); len(obs) != 1 || obs[0].KeyType != kt {
		t.Fatalf("bound table hint: %+v", obs)
	}
	// An unknown type afterwards does not rebind or close it.
	if again, err := store.Table(testSelector, testGenesis, nil, ""); err != nil || again != tb || again.KeyType() != kt {
		t.Fatalf("empty request rebound the table: %v", err)
	}
	// After a restart, opening without a type adopts the stored one, and a
	// file written while unbound is accepted under the real type.
	reopened, err := Open(paths.StageTablePath(testSelector.String()), testSelector, testGenesis)
	if err != nil || reopened.KeyType() != kt || reopened.Len() != 2 {
		t.Fatalf("reopen without type: %v type=%q len=%d", err, reopened.KeyType(), reopened.Len())
	}
	other := filepath.Join(t.TempDir(), "unbound.stages")
	unbound, _ := Open(other, testSelector, testGenesis)
	if err := put(unbound, 1, stageAddrs(1, 2)); err != nil {
		t.Fatal(err)
	}
	if typed, err := Open(other, testSelector, testGenesis, kt); err != nil || typed.Len() != 1 || typed.KeyType() != kt {
		t.Fatalf("unbound file discarded under the real type: %v", err)
	}
	// Two real, different types still mismatch.
	if _, err := Open(paths.StageTablePath(testSelector.String()), testSelector, testGenesis, "aplane.other.v1"); !errors.Is(err, ErrDiscarded) {
		t.Fatalf("different key type accepted: %v", err)
	}
}

// A hint near the top of the stage range must not wedge discovery once the
// forward stages are cached: the lower gaps are still searched.
func TestNextCandidateFallsBackWhenForwardSpaceIsExhausted(t *testing.T) {
	tb := openTest(t, t.TempDir())
	top := uint64(math.MaxUint64 - 2)
	if err := tb.RecordHint(Hint{Stage: top, Source: "backup"}); err != nil {
		t.Fatal(err)
	}
	if got := tb.NextCandidate(); got != top {
		t.Fatalf("first candidate = %d, want the hint %d", got, top)
	}
	if err := put(tb, top, stageAddrs(top, top+2)); err != nil {
		t.Fatal(err)
	}
	if got := tb.NextCandidate(); got != 0 {
		t.Fatalf("candidate after forward exhaustion = %d, want lower gap 0", got)
	}
}
