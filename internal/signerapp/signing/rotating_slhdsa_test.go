// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestSLHPreparationLimits(t *testing.T) {
	f := newRotatingFixtureFor(t, slhTestType)
	opts := StageFillOptions{Horizon: 4096, Batch: 256, MaxDerivations: 1024, Parallel: 8}
	limited := f.svc.stageFillOptions(f.account.String(), opts)
	if limited.Horizon != 2 || limited.batch() != 4 || limited.maxDerivations() != 4 || limited.parallel() != 1 {
		t.Fatalf("limits: %+v", limited)
	}
	small := f.svc.stageFillOptions(f.account.String(), StageFillOptions{Batch: 1, MaxDerivations: 1})
	if small.Horizon != 0 || small.batch() != 1 || small.maxDerivations() != 1 {
		t.Fatalf("overrode smaller caller limits: %+v", small)
	}
	r := f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Pending || r.Scanned != 3 {
		t.Fatalf("initial lookahead: %+v", r)
	}
	f.chain.authorizer = f.stageAddress(t, 1)
	r = f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Pending || r.Scanned != 4 {
		t.Fatalf("advanced lookahead: %+v", r)
	}
	// Families without a preparation ceiling retain the caller's options.
	other := newRotatingFixture(t)
	unchanged := other.svc.stageFillOptions(other.account.String(), opts)
	if unchanged.Horizon != opts.Horizon || unchanged.Batch != opts.Batch || unchanged.MaxDerivations != opts.MaxDerivations || unchanged.Parallel != opts.Parallel {
		t.Fatalf("changed WOTS limits: %+v", unchanged)
	}
}

func TestSLHDiscoveryMakesBoundedProgress(t *testing.T) {
	f, _ := newSigningFixtureFor(t, slhTestType)
	f.chain.authorizer = f.stageAddress(t, 6)
	prep, err := f.prepare(t, f.spend(1000, 1100))
	if prep != nil || err == nil || err.Kind != ErrorRotatingStageUnproven || f.table(t).Len() != 4 {
		t.Fatalf("first discovery: prep=%v err=%v scanned=%d", prep, err, f.table(t).Len())
	}
	prep = mustPrepare(t, f, f.spend(1000, 1100))
	if prep.Stage != 6 || prep.Target != 7 {
		t.Fatalf("resumed discovery: %+v", prep)
	}
}

func TestSLHRecoveryPassIncludesHintProbes(t *testing.T) {
	f := newRotatingFixtureFor(t, slhTestType)
	hint := uint64(2)
	f.chain.authorizer = f.stageAddress(t, hint)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 1, 20, time.Hour); err != nil {
		t.Fatal(err)
	}
	// One hint probe plus three prefix entries exhausts the four-derivation
	// pass. Counting only prefix growth would incorrectly add lookahead now.
	r := f.fill(t, StageFillOptions{Horizon: 4096})
	if r.Err != nil || !r.Resolved || !r.Pending || r.Scanned != 3 {
		t.Fatalf("hinted pass: %+v", r)
	}
	if st := f.state(); st.Last == nil || st.Last.Charged != 4 {
		t.Fatalf("hint accounting: %+v", st)
	}
	r = f.fill(t, StageFillOptions{Horizon: 4096})
	if r.Err != nil || !r.Resolved || r.Pending || r.Scanned != 5 {
		t.Fatalf("lookahead continuation: %+v", r)
	}
}

func TestSLHAutomaticRecoveryPassBudget(t *testing.T) {
	f := newRotatingFixtureFor(t, slhTestType)
	f.chain.authorizer = f.stageAddress(t, 9)
	for _, want := range []uint64{4, 8, 12} {
		r := f.fill(t, StageFillOptions{Horizon: 4096})
		if r.Err != nil || r.Scanned != want || r.Resolved != (want == 12) || r.Pending != (want < 12) {
			t.Fatalf("want prefix %d: %+v", want, r)
		}
	}
}

type releaseCheckChain struct {
	base      *fakeRotatingChain
	calls     int
	atRelease func()
}

func (c *releaseCheckChain) ReadAccount(ctx context.Context, genesis []byte, account types.Address) (chainread.AccountView, error) {
	c.calls++
	if c.calls == 2 {
		c.atRelease()
	}
	return c.base.ReadAccount(ctx, genesis, account)
}

func TestSLHReleaseRechecksAfterSigning(t *testing.T) {
	for _, mode := range []string{"authorizer", "expiry", "network error", "cancel", "lock generation", "locked", "removed"} {
		t.Run(mode, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, slhTestType)
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			chain := &releaseCheckChain{base: f.chain, atRelease: func() {
				switch mode {
				case "authorizer":
					f.chain.authorizer = types.Address{9}
				case "expiry":
					f.chain.round = 1095
				case "network error":
					f.chain.err = errors.New("unreachable")
				case "cancel":
					cancel()
				case "lock generation":
					f.lockGen++
				case "locked":
					f.svc.IsUnlocked = func() bool { return false }
				case "removed":
					f.present = false
				}
			}}
			f.svc.Rotating.Chain = chain
			resp, err := f.svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: f.account.String(), Transactions: prep.Transactions}, f.session)
			if chain.calls != 2 {
				t.Fatalf("chain reads %d, want two", chain.calls)
			}
			if resp != nil || err == nil {
				t.Fatalf("released after %s: response %v, error %v", mode, resp, err)
			}
			if len(audit.releases) != 0 {
				t.Fatal("aborted signature audited as released")
			}
			if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
				t.Fatal("aborted signature remembered as released")
			}
		})
	}
}

func TestSLHRestoredReleaseHasNoLeafHistory(t *testing.T) {
	f, _ := newSigningFixtureFor(t, slhTestType)
	entries := []AuditedRelease{{Account: f.account.String(), Stage: 0, TxID: "B", LastValid: 1100, Reused: true,
		Leaves: []LeafRelease{{TxID: "A"}, {TxID: "B"}}}}
	n, err := f.svc.RebuildReleaseMemory(context.Background(), f.session, entries, StageFillOptions{})
	if err != nil || n != 1 {
		t.Fatalf("restore %d: %v", n, err)
	}
	rec, ok := f.svc.Rotating.Releases.Get(f.account.String())
	if !ok || !rec.StatelessHash || rec.Reused || len(rec.Leaves) != 0 || rec.TxID != "B" {
		t.Fatalf("restored record %+v", rec)
	}
	f.svc.Rotating.Releases.Record(ReleaseRecord{Account: f.account.String(), Stage: 0, TxID: "C", LastValid: 1110, StatelessHash: true})
	_, err = f.svc.RebuildReleaseMemory(context.Background(), f.session, entries, StageFillOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ = f.svc.Rotating.Releases.Get(f.account.String())
	if rec.TxID != "C" || rec.LastValid != 1110 {
		t.Fatal("audit restore overwrote newer release")
	}
}
