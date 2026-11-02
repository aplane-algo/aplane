// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

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
