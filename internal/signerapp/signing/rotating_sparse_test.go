// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestSparseHighStagePrepareAndSignAllFamilies(t *testing.T) {
	for _, kind := range rotatingTestTypes {
		t.Run(kind.keyType, func(t *testing.T) {
			f, _ := newSigningFixtureFor(t, kind)
			n := uint64(50000)
			f.chain.authorizer = f.stageAddress(t, n)
			if err := f.table(t).SetHint(stagetable.Hint{Stage: n, Source: "backup"}); err != nil {
				t.Fatal(err)
			}
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			if prep.Stage != n || prep.Target != n+1 || f.table(t).Len() != 2 {
				t.Fatalf("prepare filled history: %+v, entries=%d", prep, f.table(t).Len())
			}
			mustSign(t, f, prep.Transactions)
			if err := f.table(t).Flush(); err != nil {
				t.Fatal(err)
			}
			// A restart distrusts loaded addresses but preserves forward search progress.
			f.tables = stagetable.NewStore(storepaths.NewPaths(f.root))
			f.svc.Rotating.Tables = f.tables
			f.chain.authorizer = f.stageAddress(t, n+2)
			prep = mustPrepare(t, f, f.spend(1000, 1100))
			if prep.Stage != n+2 || f.table(t).Len() != 4 {
				t.Fatalf("restart searched history: stage=%d entries=%d", prep.Stage, f.table(t).Len())
			}
			if _, ok := f.table(t).Address(0); ok {
				t.Fatal("derived historical prefix")
			}
		})
	}
}

func TestReleaseCandidateIsNotPersistedAsObservationOnMiss(t *testing.T) {
	f, _ := newSigningFixture(t)
	f.svc.Rotating.Releases.Record(ReleaseRecord{Account: f.account.String(), Stage: 50000})
	table := f.table(t)
	opts := StageFillOptions{searchAnchor: releaseSearchAnchor(f.svc.Rotating, f.account.String())}
	var probes []uint64
	derive := func(_ context.Context, from, to uint64) ([]types.Address, error) {
		probes = append(probes, from)
		return []types.Address{{byte(from), byte(from >> 8)}}, nil
	}
	if found, err := extendUntil(context.Background(), table, derive, types.Address{31: 255}, 4, opts); err != nil || found {
		t.Fatalf("probe: %v %v", found, err)
	}
	if len(probes) != 4 || probes[0] != 50000 || probes[3] != 50003 || table.RecoveryHint() != nil {
		t.Fatalf("release candidate became observation: %v", probes)
	}
}

func TestDerivationJobsCoalesceAndCancellationDoesNotCancelLeader(t *testing.T) {
	locks := &RotatingLocks{}
	key := stageJobKey{account: "account", from: 50000, to: 50001}
	entered := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		_, _ = locks.deriveJob(context.Background(), key, func() ([]types.Address, error) {
			calls.Add(1)
			close(entered)
			<-finish
			return []types.Address{{1}}, nil
		})
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := locks.deriveJob(ctx, key, func() ([]types.Address, error) { calls.Add(1); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	waiter := make(chan types.Address, 1)
	waiting := make(chan struct{})
	go func() {
		as, _ := locks.deriveJob(&waitObservedContext{Context: context.Background(), waiting: waiting}, key, func() ([]types.Address, error) { calls.Add(1); return []types.Address{{2}}, nil })
		waiter <- as[0]
	}()
	<-waiting
	close(finish)
	<-done
	if a := <-waiter; a != (types.Address{1}) || calls.Load() != 1 {
		t.Fatalf("shared result=%v derivations=%d", a, calls.Load())
	}
	// A new credential epoch must not reuse the old result.
	key.credential++
	if _, err := locks.deriveJob(context.Background(), key, func() ([]types.Address, error) { calls.Add(1); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("credential epoch reused stale result")
	}
}

type waitObservedContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return nil
}

func TestZeroLookaheadStillPreparesRequiredSuccessor(t *testing.T) {
	f := newRotatingFixture(t)
	r := f.fill(t, StageFillOptions{Horizon: 0, Batch: 2})
	if r.Err != nil || r.Preparation != "ready" || r.Pending || r.Scanned != 2 {
		t.Fatalf("required successor: %+v", r)
	}
}

func TestInterruptedSharedProbeRetriesForLiveWaiter(t *testing.T) {
	locks := &RotatingLocks{}
	key := stageJobKey{account: "account", from: 50000, to: 50001}
	entered := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(done)
		_, _ = locks.deriveJob(ctx, key, func() ([]types.Address, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() })
	}()
	<-entered
	waiting := make(chan struct{})
	result := make(chan types.Address, 1)
	go func() {
		as, _ := locks.deriveJob(&waitObservedContext{Context: context.Background(), waiting: waiting}, key, func() ([]types.Address, error) { return []types.Address{{3}}, nil })
		result <- as[0]
	}()
	<-waiting
	cancel()
	<-done
	if a := <-result; a != (types.Address{3}) {
		t.Fatal("live waiter lost its probe")
	}
}

// After a first single-stage probe misses, discovery derives each gap
// opts.Parallel stages at a time, never re-deriving a cached entry.
func TestExtendUntilDerivesGapsInParallelChunks(t *testing.T) {
	f, _ := newSigningFixture(t)
	table := f.table(t)
	// Stage 5 is already cached, so the chunk starting at 1 must stop before it.
	if _, err := table.RecordDerived(5, []types.Address{{5}}); err != nil {
		t.Fatal(err)
	}
	var ranges [][2]uint64
	derive := func(_ context.Context, from, to uint64) ([]types.Address, error) {
		ranges = append(ranges, [2]uint64{from, to})
		out := make([]types.Address, 0, to-from)
		for i := from; i < to; i++ {
			out = append(out, types.Address{byte(i), 1})
		}
		return out, nil
	}
	target := types.Address{9, 1}
	found, err := extendUntil(context.Background(), table, derive, target, 16, StageFillOptions{Parallel: 4})
	if err != nil || !found {
		t.Fatalf("found=%v err=%v ranges=%v", found, err, ranges)
	}
	want := [][2]uint64{{0, 1}, {1, 5}, {6, 10}}
	if len(ranges) != len(want) {
		t.Fatalf("ranges = %v, want %v", ranges, want)
	}
	for i := range want {
		if ranges[i] != want[i] {
			t.Fatalf("ranges = %v, want %v", ranges, want)
		}
	}
}

// A chunk that steps over a batch boundary still publishes once.
func TestPublishStageBatchFlushesOnBoundaryCrossing(t *testing.T) {
	f, _ := newSigningFixture(t)
	table := f.table(t)
	opts := StageFillOptions{Batch: 4, persistBatches: true}
	if _, err := table.RecordDerived(0, []types.Address{{1}, {2}, {3}}); err != nil {
		t.Fatal(err)
	}
	if err := publishStageBatch(table, 0, 3, opts); err != nil || !table.Dirty() {
		t.Fatalf("flushed before the boundary: err=%v dirty=%v", err, table.Dirty())
	}
	if err := publishStageBatch(table, 3, 6, opts); err != nil || table.Dirty() {
		t.Fatalf("boundary crossing not published: err=%v dirty=%v", err, table.Dirty())
	}
}

// A reload must not stop a running recovery grant whose credential did not
// change: the table handle survives Invalidate, so the grant keeps its search.
func TestRecoveryGrantSurvivesInventoryReload(t *testing.T) {
	rec := &RotatingRecovery{MaxStages: 1000, Timeout: time.Hour}
	rec.SetGenerationSource(func() uint64 { return 1 })
	store := stagetable.NewStore(storepaths.NewPaths(t.TempDir()))
	account := types.Address{0xA1}
	genesis := make([]byte, 32)
	table, err := store.Table(account, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := types.Address{7}
	op, svcErr := rec.StartOperator(1, account.String(), nil, 0, 500, 0)
	if svcErr != nil {
		t.Fatal(svcErr)
	}
	if g := rec.grantFor(1, account.String(), authorizer, table); g == nil || g.ID != op.ID {
		t.Fatalf("operator grant not bound: %+v", g)
	}
	store.Invalidate()
	after, err := store.Table(account, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g := rec.grantFor(1, account.String(), authorizer, after); g == nil || g.ID != op.ID {
		t.Fatalf("reload stopped the operator grant: %+v, state %+v", g, rec.State(account.String()))
	}
}
