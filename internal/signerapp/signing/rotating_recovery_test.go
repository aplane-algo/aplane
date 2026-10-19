// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func (f *rotatingFixture) recovery() *RotatingRecovery { return f.svc.Rotating.Recovery }

func (f *rotatingFixture) state() RecoveryState { return f.recovery().State(f.account.String()) }

func TestClassifyAuthorizerLadder(t *testing.T) {
	f := newRotatingFixture(t)
	f.fillUntilSettled(t, StageFillOptions{Horizon: 3})
	table := f.table(t)
	heldKey := types.Address{9, 9, 9}
	// The account's own address is also one this signer holds: stage 0 must
	// win over the inventory step.
	held := map[string]bool{f.account.String(): true, heldKey.String(): true}

	if stage, class := classifyAuthorizer(table, f.account, f.account, held); class != ClassStage || stage != 0 {
		t.Fatalf("own address: %v, %d", class, stage)
	}
	if stage, class := classifyAuthorizer(table, f.account, f.stageAddress(t, 2), held); class != ClassStage || stage != 2 {
		t.Fatalf("table hit: %v, %d", class, stage)
	}
	if _, class := classifyAuthorizer(table, f.account, heldKey, held); class != ClassHeldKey {
		t.Fatalf("held key: %v", class)
	}
	if _, class := classifyAuthorizer(table, f.account, f.stageAddress(t, 50), held); class != ClassUnknown {
		t.Fatalf("stage beyond the table: %v", class)
	}
}

func TestFillStageTablesHeldKeyAuthorizerDerivesNothing(t *testing.T) {
	f := newRotatingFixture(t)
	other := types.Address{4, 2, 31: 7}
	f.held = []string{other.String()}
	f.chain.authorizer = other
	r := f.fill(t, StageFillOptions{Horizon: 5})
	if r.Err != nil || r.Resolved || r.Pending || r.Class != ClassHeldKey || r.Scanned != 0 {
		t.Fatalf("report = %+v, want held_key, nothing derived, not pending", r)
	}
	if st := f.state(); st.Grant != nil || st.AllowanceSpent != 0 {
		t.Fatalf("a held key started a search: %+v", st)
	}
	_, notes := f.svc.RotatingStatus([]StageTableReport{r})
	if len(notes) != 1 || !strings.Contains(notes[0], "rekeyed to "+other.String()) {
		t.Fatalf("notes = %v", notes)
	}
	statuses := f.svc.RotatingAccountStatuses([]StageTableReport{r})
	if len(statuses) != 1 || statuses[0].Classification != signerapi.RotatingClassHeldKey || statuses[0].Authorizer != other.String() {
		t.Fatalf("statuses = %+v", statuses)
	}
	// A prepare refuses immediately rather than searching.
	_, err := f.prepare(t, f.spend(1000, 1050))
	if err == nil || err.Kind != ErrorBadRequest || !strings.Contains(err.Message, "rekeyed to "+other.String()) {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestAutomaticRecoveryIsBoundedPerUnlock(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(5, time.Hour)
	foreign := types.Address{0xde, 0xad, 31: 1}
	f.chain.authorizer = foreign
	opts := StageFillOptions{Horizon: 1, Batch: 2, MaxDerivations: 2}

	// Two passes of two, then the fifth and last stage of the allowance.
	for pass, want := range []uint64{2, 4} {
		r := f.fill(t, opts)
		if r.Err != nil || r.Resolved || !r.Pending || r.Scanned != want {
			t.Fatalf("pass %d = %+v", pass+1, r)
		}
		if st := f.state(); st.Grant == nil || st.Grant.Kind != GrantAutomatic || st.AllowanceSpent != want {
			t.Fatalf("pass %d state = %+v", pass+1, st)
		}
	}
	r := f.fill(t, opts)
	if r.Err != nil || r.Resolved || r.Pending || r.Scanned != 5 {
		t.Fatalf("exhausting pass = %+v, want 5 scanned and not pending", r)
	}
	st := f.state()
	if st.Grant != nil || st.Last == nil || st.Last.Reason != StopAllowanceExhausted || st.Last.Charged != 5 || st.AllowanceSpent != 5 || st.Suppressed != foreign {
		t.Fatalf("state after exhaustion = %+v", st)
	}
	// Idle from here: no grant, nothing derived, not pending.
	r = f.fill(t, opts)
	if r.Pending || r.Scanned != 5 || f.state().Grant != nil {
		t.Fatalf("suppressed pass = %+v", r)
	}
	_, notes := f.svc.RotatingStatus([]StageTableReport{r})
	if len(notes) != 1 || !strings.Contains(notes[0], "allowance exhausted after 5 stages") || !strings.Contains(notes[0], "rotate recover") {
		t.Fatalf("notes = %v", notes)
	}

	// A different unknown authorizer shares the one allowance: nothing left,
	// so it is suppressed at once and starts no grant.
	other := types.Address{0xbe, 0xef, 31: 2}
	f.chain.authorizer = other
	r = f.fill(t, opts)
	if r.Pending || r.Scanned != 5 {
		t.Fatalf("second authorizer pass = %+v", r)
	}
	if st := f.state(); st.Grant != nil || st.Suppressed != other || st.AllowanceSpent != 5 {
		t.Fatalf("second authorizer state = %+v", st)
	}

	// Lock and unlock: a new lock generation, a fresh allowance, the search
	// resumes from the table's edge.
	f.lockGen++
	f.recovery().Configure(5, time.Hour)
	r = f.fill(t, opts)
	if r.Err != nil || !r.Pending || r.Scanned != 7 {
		t.Fatalf("pass after reset = %+v, want 7 scanned and pending", r)
	}
	if st := f.state(); st.AllowanceSpent != 2 || !st.Suppressed.IsZero() {
		t.Fatalf("state after reset = %+v", st)
	}
}

func TestAutomaticRecoveryDisabledLeavesUnknownIdle(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 3)
	r := f.fill(t, StageFillOptions{Horizon: 2, Batch: 4})
	if r.Err != nil || r.Resolved || r.Pending || r.Scanned != 0 || r.Class != ClassUnknown {
		t.Fatalf("report = %+v", r)
	}
	_, notes := f.svc.RotatingStatus([]StageTableReport{r})
	if len(notes) != 1 || !strings.Contains(notes[0], "automatic recovery is disabled") {
		t.Fatalf("notes = %v", notes)
	}
	// An operator grant still works.
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 10, 0); err != nil {
		t.Fatal(err)
	}
	r = f.fillUntilSettled(t, StageFillOptions{Horizon: 2, Batch: 4})
	if r.Err != nil || !r.Resolved || r.Stage != 3 {
		t.Fatalf("operator report = %+v", r)
	}
	if st := f.state(); st.AllowanceSpent != 0 || st.Last == nil || st.Last.Reason != StopFound || st.Last.Kind != GrantOperator {
		t.Fatalf("state = %+v", st)
	}
}

func TestAutomaticRecoveryFindsGapBeyondHorizonFromTableEdge(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(4, time.Hour)
	opts := StageFillOptions{Horizon: 2, Batch: 8}
	// Stage 0 live, table filled to the horizon: stages 0 … 2.
	if r := f.fillUntilSettled(t, opts); r.Scanned != 3 {
		t.Fatalf("initial fill = %+v", r)
	}
	// Another signer advanced the account to stage 6, four past the
	// table's edge: exactly the allowance, counted from the edge.
	f.chain.authorizer = f.stageAddress(t, 6)
	r := f.fillUntilSettled(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 6 || r.Scanned != 9 {
		t.Fatalf("report = %+v, want stage 6 resolved and lookahead to 8", r)
	}
	st := f.state()
	if st.Grant != nil || st.Last == nil || st.Last.Reason != StopFound || st.Last.Stage == nil || *st.Last.Stage != 6 || st.AllowanceSpent != 4 {
		t.Fatalf("state = %+v", st)
	}
	// A second gap in the same unlock has nothing left: suppressed, idle,
	// and the table does not move.
	f.chain.authorizer = f.stageAddress(t, 20)
	r = f.fill(t, opts)
	if r.Pending || r.Scanned != 9 || f.state().Suppressed != f.stageAddress(t, 20) {
		t.Fatalf("second gap = %+v, state %+v", r, f.state())
	}
}

func TestOperatorGrantReplacesAutomaticAndRejectsASecond(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	opts := StageFillOptions{Horizon: 1, Batch: 2, MaxDerivations: 2}
	f.fill(t, opts)
	auto := f.state().Grant
	if auto == nil || auto.Kind != GrantAutomatic {
		t.Fatalf("no automatic grant: %+v", f.state())
	}

	op, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	st := f.state()
	if st.Grant == nil || st.Grant.ID != op.ID || st.Grant.Kind != GrantOperator {
		t.Fatalf("operator grant not active: %+v", st)
	}
	if st.Last == nil || st.Last.GrantID != auto.ID || st.Last.Reason != StopSuperseded || st.AllowanceSpent != 2 {
		t.Fatalf("automatic grant not superseded with its charge kept: %+v", st)
	}
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 3, 0); err == nil || !strings.Contains(err.Message, "cancel it first") {
		t.Fatalf("second operator grant: %v", err)
	}

	// The operator grant runs with its own budget: exactly 3 more stages,
	// none of them charged to the allowance, then it stops.
	f.fill(t, opts)
	r := f.fill(t, opts)
	if r.Scanned != 5 || r.Pending {
		t.Fatalf("operator passes = %+v", r)
	}
	st = f.state()
	if st.Grant != nil || st.Last == nil || st.Last.GrantID != op.ID || st.Last.Reason != StopBudgetExhausted || st.Last.Charged != 3 || st.AllowanceSpent != 2 {
		t.Fatalf("state after operator budget = %+v", st)
	}
	// Nothing to cancel now.
	if id := f.recovery().Cancel(f.lockGen, f.account.String()); id != 0 {
		t.Fatalf("cancel of nothing = %d", id)
	}
	// The automatic allowance is untouched by the operator's work, so the
	// automatic search resumes for the still-unknown authorizer.
	r = f.fill(t, opts)
	if !r.Pending || r.Scanned != 7 || f.state().AllowanceSpent != 4 {
		t.Fatalf("automatic resume = %+v, state %+v", r, f.state())
	}
}

func TestOperatorGrantBudgetCapsWithinOneBatch(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 3, 0); err != nil {
		t.Fatal(err)
	}
	// A batch of 256 and a pass budget of 256, but a grant of 3: three
	// derivations, not a batch.
	r := f.fill(t, StageFillOptions{Horizon: 1, Batch: 256, MaxDerivations: 256})
	if r.Err != nil || r.Pending || r.Scanned != 3 {
		t.Fatalf("report = %+v, want exactly 3 derived", r)
	}
	if st := f.state(); st.Grant != nil || st.Last == nil || st.Last.Reason != StopBudgetExhausted || st.Last.Charged != 3 {
		t.Fatalf("state = %+v", st)
	}
}

func TestOperatorGrantCancelLandsBetweenDerivations(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 100, 0); err != nil {
		t.Fatal(err)
	}
	derived := 0
	var cancelled uint64
	opts := StageFillOptions{Horizon: 1, Batch: 50, MaxDerivations: 50, Pace: func(time.Duration) {
		derived++
		if derived == 2 {
			cancelled = f.recovery().Cancel(f.lockGen, f.account.String())
		}
	}}
	r := f.fill(t, opts)
	if r.Err != nil || r.Pending || cancelled == 0 {
		t.Fatalf("report = %+v, cancelled %d", r, cancelled)
	}
	// The two derivations before the cancel are kept and charged; the
	// batch did not run on.
	if r.Scanned != 2 {
		t.Fatalf("scanned = %d, want 2", r.Scanned)
	}
	if st := f.state(); st.Grant != nil || st.Last == nil || st.Last.Reason != StopCancelled || st.Last.Charged != 2 {
		t.Fatalf("state = %+v", st)
	}
}

func TestOperatorGrantTimeoutIsActiveTime(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	// A timeout no derivation can beat: the first derivation runs, the
	// second is refused.
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 100, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	r := f.fill(t, StageFillOptions{Horizon: 1, Batch: 10, MaxDerivations: 10})
	if r.Err != nil || r.Pending || r.Scanned != 1 {
		t.Fatalf("report = %+v, want one derivation then timeout", r)
	}
	if st := f.state(); st.Grant != nil || st.Last == nil || st.Last.Reason != StopTimedOut || st.Last.Charged != 1 {
		t.Fatalf("state = %+v", st)
	}
}

func TestAutomaticTimeoutSuppressesTheAuthorizer(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Nanosecond)
	foreign := types.Address{0xde, 0xad, 31: 1}
	f.chain.authorizer = foreign
	r := f.fill(t, StageFillOptions{Horizon: 1, Batch: 10, MaxDerivations: 10})
	if r.Err != nil || r.Pending || r.Scanned != 1 {
		t.Fatalf("report = %+v", r)
	}
	if st := f.state(); st.Grant != nil || st.Last == nil || st.Last.Reason != StopTimedOut || st.Suppressed != foreign {
		t.Fatalf("state = %+v", st)
	}
}

func TestHintedRecoveryExactHint(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 10)
	hint := uint64(10)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 3, 100, 0); err != nil {
		t.Fatal(err)
	}
	opts := StageFillOptions{Horizon: 2, Batch: 8}
	// First pass: one probe matches; the grant then fills the gap with
	// the rest of the pass budget (one batch of 8, so 7 stages).
	r := f.fill(t, opts)
	if r.Err != nil || r.Resolved || !r.Pending || r.Scanned != 7 {
		t.Fatalf("first pass = %+v", r)
	}
	if st := f.state(); st.Grant == nil || st.Grant.Found == nil || *st.Grant.Found != 10 || st.Grant.Charged != 8 {
		t.Fatalf("state after probe = %+v", st)
	}
	r = f.fillUntilSettled(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 10 || r.Scanned != 13 {
		t.Fatalf("settled = %+v, want stage 10 and lookahead to 12", r)
	}
	// One probe plus eleven stages of gap (0 … 10).
	if st := f.state(); st.Last == nil || st.Last.Reason != StopFound || st.Last.Charged != 12 || st.AllowanceSpent != 0 {
		t.Fatalf("final state = %+v", st)
	}
}

func TestHintedRecoveryOffByAFewProbesOutward(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 10)
	hint := uint64(8)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 3, 100, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fillUntilSettled(t, StageFillOptions{Horizon: 0, Batch: 64})
	if r.Err != nil || !r.Resolved || r.Stage != 10 {
		t.Fatalf("report = %+v", r)
	}
	// Probes 8, 9, 7, 10: four derivations, then eleven for the gap.
	if st := f.state(); st.Last == nil || st.Last.Reason != StopFound || st.Last.Charged != 4+11 {
		t.Fatalf("state = %+v", st)
	}
}

func TestHintedRecoveryWrongHintExhaustsTheWindowAndLeavesTheTable(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 10)
	hint := uint64(100)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 2, 100, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fillUntilSettled(t, StageFillOptions{Horizon: 0, Batch: 64})
	if r.Err != nil || r.Resolved || r.Scanned != 0 {
		t.Fatalf("report = %+v, want unresolved with an untouched table", r)
	}
	// Probes 100, 101, 99, 102, 98: five derivations, no match.
	if st := f.state(); st.Grant != nil || st.Last == nil || st.Last.Reason != StopHintNotFound || st.Last.Charged != 5 {
		t.Fatalf("state = %+v", st)
	}
}

func TestHintedRecoveryGapFillStopsAtTheBudget(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 10)
	hint := uint64(10)
	// Budget 5: the probe plus four stages of gap, then it stops with the
	// progress kept; a second grant with a bigger budget finishes.
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 0, 5, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fillUntilSettled(t, StageFillOptions{Horizon: 0, Batch: 64})
	if r.Err != nil || r.Resolved || r.Scanned != 4 {
		t.Fatalf("report = %+v, want 4 stages filled", r)
	}
	if st := f.state(); st.Last == nil || st.Last.Reason != StopBudgetExhausted || st.Last.Charged != 5 {
		t.Fatalf("state = %+v", st)
	}
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 0, 100, 0); err != nil {
		t.Fatal(err)
	}
	r = f.fillUntilSettled(t, StageFillOptions{Horizon: 0, Batch: 64})
	if r.Err != nil || !r.Resolved || r.Stage != 10 || r.Scanned != 11 {
		t.Fatalf("second grant = %+v", r)
	}
	// One probe plus the remaining seven stages (4 … 10).
	if st := f.state(); st.Last.Charged != 8 {
		t.Fatalf("second grant charge = %+v", st.Last)
	}
}

func TestRecoveryGrantEndsWhenTheAuthorizerChanges(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	opts := StageFillOptions{Horizon: 1, Batch: 2, MaxDerivations: 2}
	f.fill(t, opts)
	first := f.state().Grant
	// The chain now shows a stage this signer can reach: the old grant
	// ends, its charge stands, and a new automatic grant finds the stage.
	f.chain.authorizer = f.stageAddress(t, 3)
	r := f.fillUntilSettled(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 3 {
		t.Fatalf("report = %+v", r)
	}
	st := f.state()
	if st.Last == nil || st.Last.Reason != StopFound || st.Last.GrantID == first.ID || st.AllowanceSpent != 4 {
		t.Fatalf("state = %+v (first grant %d)", st, first.ID)
	}
}

func TestRecoveryGrantOnAnAlreadyResolvedAccountEndsAtTheNextObservation(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	opts := StageFillOptions{Horizon: 2, Batch: 8}
	f.fillUntilSettled(t, opts)

	// An operator grants a search for a stage the signer already has: the
	// next pass ends it as resolved, charging nothing, and a new grant is
	// accepted rather than refused with "cancel it first".
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 10, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 0 {
		t.Fatalf("report = %+v", r)
	}
	st := f.state()
	if st.Grant != nil || st.Last == nil || st.Last.Reason != StopResolved || st.Last.Stage == nil || *st.Last.Stage != 0 || st.Last.Charged != 0 {
		t.Fatalf("state = %+v", st)
	}
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 10, 0); err != nil {
		t.Fatalf("second grant refused: %v", err)
	}

	// The account moves to a key this signer holds while the grant is
	// pending: the grant ends too.
	other := types.Address{4, 2, 31: 7}
	f.held = []string{other.String()}
	f.chain.authorizer = other
	r = f.fill(t, opts)
	if r.Err != nil || r.Class != ClassHeldKey {
		t.Fatalf("held-key report = %+v", r)
	}
	if st := f.state(); st.Grant != nil || st.Last == nil || st.Last.Reason != StopHeldKey {
		t.Fatalf("state after held key = %+v", st)
	}
}

func TestCancelledPassDoesNotPruneOrBind(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	f.lockGen = 2
	opts := StageFillOptions{Horizon: 1, Batch: 2, MaxDerivations: 2}
	f.fill(t, opts)
	before := f.state()
	if before.Grant == nil || before.AllowanceSpent != 2 {
		t.Fatalf("state = %+v", before)
	}

	// An old pass, cancelled by a lock, resumes while the signer is locked:
	// its inventory is empty and the generation it would read is the one a
	// later unlock will share. It must do nothing at all.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	f.present = false
	if reports := f.svc.FillStageTables(cancelled, f.session, opts); reports != nil {
		t.Fatalf("cancelled pass reported work: %+v", reports)
	}
	f.present = true
	if st := f.state(); st.Grant == nil || st.Grant.ID != before.Grant.ID || st.AllowanceSpent != 2 {
		t.Fatalf("cancelled pass pruned the current session: %+v", st)
	}

	// A pass whose captured session is not the live one is refused even
	// with a live context, whether a lock and unlock happened between
	// capturing the session and creating the context (captured 1, live 2)
	// or after the context existed (captured 2, live 3).
	for _, captured := range []uint64{1, 2} {
		f.lockGen = captured + 1
		c := captured
		staleOpts := opts
		staleOpts.Session = &c
		if reports := f.svc.FillStageTables(context.Background(), f.session, staleOpts); reports != nil {
			t.Fatalf("captured %d, live %d: pass reported work: %+v", captured, f.lockGen, reports)
		}
	}
	// The sessions that ended took their state with them; the live one
	// starts clean and a pass carrying it works.
	if st := f.state(); st.Grant != nil || st.AllowanceSpent != 0 {
		t.Fatalf("ended sessions left state behind: %+v", st)
	}
	live := f.lockGen
	liveOpts := opts
	liveOpts.Session = &live
	if reports := f.svc.FillStageTables(context.Background(), f.session, liveOpts); len(reports) != 1 {
		t.Fatalf("live-session pass = %+v", reports)
	}
	if st := f.state(); st.Grant == nil || st.AllowanceSpent != 2 {
		t.Fatalf("live session did not start: %+v", st)
	}
}

// TestSessionOwnershipMatrix is the lifecycle contract in one place. For
// every operation on the recovery memory and every point at which a lock
// and unlock can land relative to it, with and without another request
// having observed the new session first, the operation of the ended
// session is refused and the new session's state is exactly what the new
// session put there.
func TestSessionOwnershipMatrix(t *testing.T) {
	type op struct {
		name string
		// run performs the operation as a caller that captured gen.
		run func(rec *RotatingRecovery, gen uint64, g *RecoveryGrant)
	}
	ops := []op{
		{"start operator", func(rec *RotatingRecovery, gen uint64, _ *RecoveryGrant) {
			if _, err := rec.StartOperator(gen, "A", nil, 0, 5, 0); err == nil || err.Kind != ErrorUnavailable {
				t.Fatalf("stale start: %v", err)
			}
		}},
		{"cancel", func(rec *RotatingRecovery, gen uint64, _ *RecoveryGrant) {
			if rec.Cancel(gen, "A") != 0 {
				t.Fatal("stale cancel cancelled something")
			}
		}},
		{"automatic grant", func(rec *RotatingRecovery, gen uint64, _ *RecoveryGrant) {
			if rec.grantFor(gen, "A", types.Address{7}, nil) != nil {
				t.Fatal("stale pass granted")
			}
		}},
		{"reconcile", func(rec *RotatingRecovery, gen uint64, _ *RecoveryGrant) {
			rec.reconcile(gen, "A", StopResolved, nil)
		}},
		{"prune", func(rec *RotatingRecovery, gen uint64, _ *RecoveryGrant) {
			rec.Prune(gen, func(string) bool { return false })
		}},
		{"charge during work", func(rec *RotatingRecovery, _ uint64, g *RecoveryGrant) {
			rec.charge(g, 4, time.Second)
			if rec.allow(g) != 0 || rec.progress(g) {
				t.Fatal("stale grant still allowed to run")
			}
		}},
		{"finish during work", func(rec *RotatingRecovery, _ uint64, g *RecoveryGrant) {
			stage := uint64(9)
			rec.finish(g, StopFound, &stage)
			rec.setFound(g, 9)
		}},
	}
	for _, observed := range []bool{false, true} {
		for _, o := range ops {
			name := o.name + "/unobserved"
			if observed {
				name = o.name + "/observed"
			}
			t.Run(name, func(t *testing.T) {
				gen := uint64(1)
				rec := &RotatingRecovery{MaxStages: 10, Timeout: time.Hour}
				rec.SetGenerationSource(func() uint64 { return gen })
				// Session 1: the operation captures its session and, for
				// the in-work cases, holds a grant it already charged.
				old := rec.grantFor(1, "A", types.Address{1}, nil)
				rec.charge(old, 3, 0)
				captured := rec.Session()

				// Lock and unlock. Optionally a request of session 2 acts
				// first, so the memory has already observed it.
				gen = 2
				var fresh *RecoveryGrant
				if observed {
					fresh = rec.grantFor(2, "A", types.Address{2}, nil)
					rec.charge(fresh, 1, 0)
				}

				o.run(rec, captured, old)

				st := rec.State("A")
				switch {
				case observed:
					if st.Grant == nil || st.Grant.ID != fresh.ID || st.AllowanceSpent != 1 || st.Last != nil {
						t.Fatalf("stale %s changed session 2: %+v", o.name, st)
					}
				default:
					if st.Grant != nil || st.AllowanceSpent != 0 || st.Last != nil {
						t.Fatalf("stale %s left state in session 2: %+v", o.name, st)
					}
				}
				// Session 2 is fully usable afterwards, with its whole allowance.
				g2 := rec.grantFor(2, "A", types.Address{3}, nil)
				if observed {
					// The fresh grant is still the active one for a new authorizer? No:
					// a changed authorizer ends it and a new grant uses the remainder.
					if g2 == nil || g2.MaxStages != 9 {
						t.Fatalf("session 2 after stale %s: grant %+v", o.name, g2)
					}
				} else if g2 == nil || g2.MaxStages != 10 {
					t.Fatalf("session 2 after stale %s: grant %+v", o.name, g2)
				}
			})
		}
	}
}

func TestRecoveryChargeAfterReplacementStillCounts(t *testing.T) {
	gen := uint64(1)
	rec := &RotatingRecovery{MaxStages: 10, Timeout: time.Hour}
	rec.SetGenerationSource(func() uint64 { return gen })
	authorizer := types.Address{1}
	auto := rec.grantFor(1, "A", authorizer, nil)
	rec.charge(auto, 2, time.Second)
	// An operator request supersedes the automatic grant while one of its
	// derivations is still running; that derivation completes afterwards.
	op, err := rec.StartOperator(1, "A", nil, 0, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec.charge(auto, 1, time.Second)
	st := rec.State("A")
	if st.AllowanceSpent != 3 || st.Last == nil || st.Last.GrantID != auto.ID || st.Last.Charged != 3 {
		t.Fatalf("superseded grant's late derivation not counted: %+v", st)
	}
	if st.Grant == nil || st.Grant.ID != op.ID || st.Grant.Charged != 0 {
		t.Fatalf("operator grant charged for the automatic grant's work: %+v", st.Grant)
	}
	// Likewise after a cancel: the operator grant's stop record grows, the
	// allowance does not.
	rec.Cancel(1, "A")
	rec.charge(op, 4, 0)
	st = rec.State("A")
	if st.AllowanceSpent != 3 || st.Last == nil || st.Last.GrantID != op.ID || st.Last.Charged != 4 {
		t.Fatalf("cancelled grant's late derivation: %+v", st)
	}
	// Only another session discards the charge.
	gen = 2
	rec.charge(auto, 5, 0)
	if st := rec.State("A"); st.AllowanceSpent != 0 {
		t.Fatalf("stale epoch charged: %+v", st)
	}
	// The grant's own allowance check is what stops it running on: a
	// superseded grant is allowed nothing more.
	if rec.allow(auto) != 0 {
		t.Fatal("superseded grant still allowed to derive")
	}
}

func TestRecoveryAccountingSurvivesStaleEpochsAndPrune(t *testing.T) {
	gen := uint64(1)
	rec := &RotatingRecovery{MaxStages: 10, Timeout: time.Hour}
	rec.SetGenerationSource(func() uint64 { return gen })
	authorizer := types.Address{1}
	g := rec.grantFor(1, "A", authorizer, nil)
	if g == nil {
		t.Fatal("no grant")
	}
	rec.charge(g, 3, time.Second)
	if st := rec.State("A"); st.AllowanceSpent != 3 || st.Grant == nil || st.Grant.Charged != 3 {
		t.Fatalf("state = %+v", st)
	}
	// A new session: the stale grant cannot charge, finish or report into
	// it.
	gen = 2
	rec.charge(g, 5, time.Second)
	rec.finish(g, StopFound, nil)
	if st := rec.State("A"); st.AllowanceSpent != 0 || st.Grant != nil || st.Last != nil {
		t.Fatalf("stale grant leaked into the new epoch: %+v", st)
	}
	if rec.allow(g) != 0 || rec.progress(g) {
		t.Fatal("stale grant still allowed to run")
	}

	// Prune of a removed credential drops its grant and stop but keeps the
	// allowance spent in this epoch.
	g = rec.grantFor(2, "A", authorizer, nil)
	rec.charge(g, 4, 0)
	rec.Prune(2, func(string) bool { return false })
	if st := rec.State("A"); st.AllowanceSpent != 4 || st.Grant != nil || st.Last != nil {
		t.Fatalf("state after prune = %+v", st)
	}
	// Re-imported within the epoch: only the remaining allowance is granted.
	g = rec.grantFor(2, "A", authorizer, nil)
	if g == nil || g.MaxStages != 6 {
		t.Fatalf("grant after prune = %+v", g)
	}
}

func TestRecoveryGrantEndsWhenTheCredentialIsReplaced(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	opts := StageFillOptions{Horizon: 1, Batch: 2, MaxDerivations: 2}
	f.fill(t, opts)
	first := f.state().Grant
	// The table is discarded and reopened: a new credential generation.
	if err := f.tables.Discard(f.table(t)); err != nil {
		t.Fatal(err)
	}
	r := f.fill(t, opts)
	if r.Err != nil || !r.Pending {
		t.Fatalf("report = %+v", r)
	}
	st := f.state()
	if st.Grant == nil || st.Grant.ID == first.ID || st.AllowanceSpent != 4 {
		t.Fatalf("state = %+v, want a new grant with the old charge kept", st)
	}
}

func TestRecoverRotatingServiceStartsAndCancels(t *testing.T) {
	f := newRotatingFixture(t)
	acct := f.account.String()
	ctx := context.Background()

	if _, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: acct, Action: "restart"}); err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("bad action: %v", err)
	}
	if _, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: types.Address{1}.String(), Action: "start"}); err == nil || !strings.Contains(err.Message, "no key found") {
		t.Fatalf("unknown account: %v", err)
	}
	f.held = []string{types.Address{2}.String()}
	if _, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: types.Address{2}.String(), Action: "start"}); err == nil || !strings.Contains(err.Message, "not a rotating account") {
		t.Fatalf("non-rotating account: %v", err)
	}
	if _, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: acct, Action: "start", Window: MaxRecoveryHintWindow + 1}); err == nil || !strings.Contains(err.Message, "window") {
		t.Fatalf("oversized window: %v", err)
	}

	hint := uint64(12)
	resp, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: acct, Action: "start", Stage: &hint, MaxStages: 7})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GrantID == 0 || !resp.Recovery.Active || resp.Recovery.Kind != signerapi.RotatingRecoveryOperator || resp.Recovery.MaxStages != 7 || resp.Recovery.Hint == nil || *resp.Recovery.Hint != 12 {
		t.Fatalf("start response = %+v", resp)
	}
	if _, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: acct, Action: "start"}); err == nil || !strings.Contains(err.Message, "cancel it first") {
		t.Fatalf("second start: %v", err)
	}
	cancel, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: acct, Action: "cancel"})
	if err != nil {
		t.Fatal(err)
	}
	if cancel.GrantID != resp.GrantID || cancel.Recovery.Active || cancel.Recovery.Stopped != StopCancelled {
		t.Fatalf("cancel response = %+v", cancel)
	}
	again, err := f.svc.RecoverRotatingWithContext(ctx, signerapi.RotatingRecoverRequest{Account: acct, Action: "cancel"})
	if err != nil || again.GrantID != 0 {
		t.Fatalf("cancel of nothing = %+v, %v", again, err)
	}
}

func TestRotatingAccountStatusesProjection(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(3, time.Hour)
	foreign := types.Address{0xde, 0xad, 31: 1}
	f.chain.authorizer = foreign
	opts := StageFillOptions{Horizon: 1, Batch: 2, MaxDerivations: 2}
	r := f.fill(t, opts)
	got := f.svc.RotatingAccountStatuses([]StageTableReport{r})
	if len(got) != 1 {
		t.Fatalf("statuses = %+v", got)
	}
	st := got[0]
	if st.Account != f.account.String() || st.Authorizer != foreign.String() || st.Round != 1000 || st.Classification != signerapi.RotatingClassUnknown || st.Stage != nil || st.CachedStages != 2 {
		t.Fatalf("status = %+v", st)
	}
	if st.Recovery == nil || !st.Recovery.Active || st.Recovery.Kind != "automatic" || st.Recovery.StagesCharged != 2 || st.Recovery.MaxStages != 3 || st.Recovery.AllowanceSpent != 2 || st.Recovery.AllowanceMax != 3 {
		t.Fatalf("recovery = %+v", st.Recovery)
	}
	r = f.fill(t, opts)
	st = f.svc.RotatingAccountStatuses([]StageTableReport{r})[0]
	if st.Recovery == nil || st.Recovery.Active || st.Recovery.Stopped != StopAllowanceExhausted || st.Recovery.SuppressedAuthorizer != foreign.String() || st.Recovery.StoppedKind != "automatic" {
		t.Fatalf("recovery after exhaustion = %+v", st.Recovery)
	}
	// A resolved account reports its stage and no recovery block once
	// nothing has happened to it in this unlock.
	f.lockGen++
	f.chain.authorizer = f.account
	r = f.fillUntilSettled(t, opts)
	st = f.svc.RotatingAccountStatuses([]StageTableReport{r})[0]
	if st.Classification != signerapi.RotatingClassStage || st.Stage == nil || *st.Stage != 0 || st.Recovery != nil {
		t.Fatalf("resolved status = %+v", st)
	}
	// A failed read: unobserved, with the cache size still reported.
	st = f.svc.RotatingAccountStatuses([]StageTableReport{{Account: f.account.String(), Scanned: 5}})[0]
	if st.Classification != signerapi.RotatingClassUnobserved || st.Authorizer != "" || st.CachedStages != 5 {
		t.Fatalf("unobserved status = %+v", st)
	}
}
