// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
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

func TestStatelessStageCountsDistinctReleases(t *testing.T) {
	const budget = 3
	rel := func(account string, stage uint64, txid string) ReleaseRecord {
		return ReleaseRecord{Account: account, Stage: stage, TxID: txid, StatelessHash: true, MessageBudget: budget}
	}
	distinct := func(m *ReleaseMemory, account string) int {
		rec, ok := m.Get(account)
		if !ok {
			t.Fatalf("no record for %s", account)
		}
		return rec.Distinct
	}
	m := &ReleaseMemory{}
	m.Record(rel("A", 0, "T1"))
	m.Record(rel("A", 0, "T1")) // a retry is one release
	m.Record(rel("A", 0, "T2"))
	if got := distinct(m, "A"); got != 2 {
		t.Fatalf("distinct after a retry and a second transaction = %d, want 2", got)
	}
	// The count saturates one past the budget, so it stays bounded.
	for _, id := range []string{"T3", "T4", "T5", "T6"} {
		m.Record(rel("A", 0, id))
	}
	if got := distinct(m, "A"); got != budget+1 {
		t.Fatalf("saturated count = %d, want %d", got, budget+1)
	}
	// A later stage starts a fresh count; so does an account the memory forgot.
	m.Record(rel("A", 1, "T1"))
	if got := distinct(m, "A"); got != 1 {
		t.Fatalf("count at the next stage = %d, want 1", got)
	}
	m.Clear("A")
	m.Record(rel("A", 1, "T9"))
	if got := distinct(m, "A"); got != 1 {
		t.Fatalf("count after the account was forgotten = %d, want 1", got)
	}
	// A family without a budget keeps no per-release state.
	m.Record(ReleaseRecord{Account: "B", Stage: 0, TxID: "X", StatelessHash: true})
	if got := distinct(m, "B"); got != 0 || m.messages["B"] != nil {
		t.Fatalf("budgetless stateless family tracked releases: distinct %d", got)
	}

	// The audit log's history counts toward the stage, the live release
	// stays the newest, and a log from an earlier stage is ignored.
	m = &ReleaseMemory{}
	m.Record(rel("C", 2, "L1"))
	m.RecordAudited(ReleaseRecord{Account: "C", Stage: 2, TxID: "A2", StatelessHash: true, MessageBudget: budget,
		Leaves: []LeafRelease{{TxID: "A1"}, {TxID: "A2"}}})
	rec, _ := m.Get("C")
	if rec.Distinct != 3 || rec.TxID != "L1" {
		t.Fatalf("audited history merged into a live stage: %+v", rec)
	}
	m.RecordAudited(ReleaseRecord{Account: "C", Stage: 1, TxID: "OLD", StatelessHash: true, MessageBudget: budget})
	if rec, _ = m.Get("C"); rec.Distinct != 3 || rec.Stage != 2 {
		t.Fatalf("a log from an earlier stage changed the record: %+v", rec)
	}
	m.Reset()
	m.Record(rel("C", 2, "L2"))
	if got := distinct(m, "C"); got != 1 {
		t.Fatalf("count after a reset = %d, want 1", got)
	}
}

func TestSLHStatusWarnsPastTheMessageBudget(t *testing.T) {
	f, _ := newSigningFixtureFor(t, slhTestType)
	profile, _ := rotatingkey.Lookup(slhTestType.keyType)
	budget := profile.StageMessageBudget
	if budget == 0 {
		t.Fatal("the SLH-DSA profile has no stage message budget")
	}
	acct := f.account.String()
	stage0, stage1 := f.stageAddress(t, 0), f.stageAddress(t, 1)
	release := func(id int) {
		f.svc.Rotating.Releases.Record(ReleaseRecord{
			Account: acct, Stage: 0, StageAddr: stage0, NextAddr: stage1,
			TxID: fmt.Sprintf("T%d", id), LastValid: 1100, StatelessHash: true, MessageBudget: budget,
		})
	}
	status := func(authorizer types.Address) ([]string, []string) {
		return f.svc.RotatingStatus([]StageTableReport{{
			Account: acct, Observed: true, Resolved: true, Authorizer: authorizer, Round: 1050,
			ObservedSeq: f.svc.Rotating.Releases.Seq(),
		}})
	}
	for i := 0; i < budget; i++ {
		release(i)
	}
	release(0) // a retry does not count
	if warnings, notes := status(stage0); len(warnings) != 0 || len(notes) != 1 {
		t.Fatalf("at the budget: warnings %v, notes %v", warnings, notes)
	}
	release(budget)
	warnings, notes := status(stage0)
	if len(warnings) != 1 || len(notes) != 0 || !strings.Contains(warnings[0], fmt.Sprintf("more than %d distinct", budget)) || !strings.Contains(warnings[0], fmt.Sprintf("T%d", budget)) {
		t.Fatalf("past the budget: warnings %v, notes %v", warnings, notes)
	}
	// More releases do not change the text, so it is logged once.
	release(budget + 1)
	if again, _ := status(stage0); len(again) != 1 || !strings.Contains(again[0], "more than") {
		t.Fatalf("warning after more releases: %v", again)
	}
	// Signing is never refused: the warning is the whole response.
	// Landed: the stage is retired and the count goes with it.
	if warnings, notes := status(stage1); len(warnings) != 0 || len(notes) != 0 {
		t.Fatalf("landed: warnings %v, notes %v", warnings, notes)
	}
	release(0)
	if rec, _ := f.svc.Rotating.Releases.Get(acct); rec.Distinct != 1 {
		t.Fatalf("count did not restart after the account moved: %+v", rec)
	}
}

func TestSLHRestoredHistoryCountsTowardTheMessageBudget(t *testing.T) {
	f, _ := newSigningFixtureFor(t, slhTestType)
	profile, _ := rotatingkey.Lookup(slhTestType.keyType)
	budget := profile.StageMessageBudget
	leaves := make([]LeafRelease, 0, budget+1)
	for i := 0; i <= budget; i++ {
		leaves = append(leaves, LeafRelease{TxID: fmt.Sprintf("T%d", i)})
	}
	n, err := f.svc.RebuildReleaseMemory(context.Background(), f.session, []AuditedRelease{{
		Account: f.account.String(), Stage: 0, TxID: leaves[budget].TxID, LastValid: 1100, Leaves: leaves,
	}}, StageFillOptions{})
	if err != nil || n != 1 {
		t.Fatalf("restore %d: %v", n, err)
	}
	warnings, _ := f.svc.RotatingStatus([]StageTableReport{{
		Account: f.account.String(), Observed: true, Resolved: true, Authorizer: f.stageAddress(t, 0),
		Round: 1050, ObservedSeq: f.svc.Rotating.Releases.Seq(),
	}})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "distinct transactions") {
		t.Fatalf("restored history past the budget: %v", warnings)
	}
}
