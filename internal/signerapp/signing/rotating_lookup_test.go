// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The worker's search for an unknown authorizer begins with one chain
// lookup per grant (spec: rotating stage lookup, section 5). These tests
// drive it through FillStageTables with a fake lookup.

const lookupTestTxID = "LOOKUPTESTTXID"

// answerCandidate makes the fixture's lookup propose stage n.
func (f *rotatingFixture) answerCandidate(n uint64) {
	f.chain.lookup = func(context.Context, types.Address, types.Address) (chainread.StageLookup, error) {
		return chainread.StageLookup{Outcome: chainread.LookupCandidate, Network: "testnet", Host: "indexer.example", Stage: n, TxID: lookupTestTxID, Round: 900}, nil
	}
}

// answerOutcome makes the fixture's lookup give outcome, with no candidate.
func (f *rotatingFixture) answerOutcome(outcome chainread.LookupOutcome) {
	f.chain.lookup = func(context.Context, types.Address, types.Address) (chainread.StageLookup, error) {
		return chainread.StageLookup{Outcome: outcome, Network: "testnet", Host: "indexer.example", Reason: "test"}, nil
	}
}

// derivedOrder records the order in which passes add stages to a fixture's
// table. With one derivation at a time, each derivation is recorded by the
// time the next one paces, so noting new stages at every pace and at the end
// of each pass gives the exact sequence.
type derivedOrder struct {
	f     *rotatingFixture
	t     *testing.T
	seen  map[uint64]bool
	order []uint64
}

const derivedOrderLimit = 256

func newDerivedOrder(t *testing.T, f *rotatingFixture) *derivedOrder {
	d := &derivedOrder{f: f, t: t, seen: map[uint64]bool{}}
	d.note()
	d.order = nil
	return d
}

func (d *derivedOrder) note() {
	table := d.f.table(d.t)
	for n := uint64(0); n < derivedOrderLimit; n++ {
		if _, ok := table.Address(n); ok && !d.seen[n] {
			d.seen[n] = true
			d.order = append(d.order, n)
		}
	}
}

// fill runs one pass with opts, noting the stages it derives.
func (d *derivedOrder) fill(opts StageFillOptions) StageTableReport {
	pace := opts.Pace
	opts.Pace = func(elapsed time.Duration) {
		d.note()
		if pace != nil {
			pace(elapsed)
		}
	}
	r := d.f.fill(d.t, opts)
	d.note()
	return r
}

func TestLookupCandidateThatMatchesEndsTheSearchAfterOneDerivation(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 37)
	f.answerCandidate(37)
	d := newDerivedOrder(t, f)
	r := d.fill(StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if r.Err != nil || !r.Resolved || r.Stage != 37 {
		t.Fatalf("report = %+v, want stage 37 resolved", r)
	}
	if len(d.order) < 1 || d.order[0] != 37 {
		t.Fatalf("derived %v, want stage 37 first", d.order)
	}
	st := f.state()
	if st.Grant != nil || st.Last == nil || st.Last.Reason != StopFound || st.Last.Stage == nil || *st.Last.Stage != 37 || st.Last.Charged != 1 || st.AllowanceSpent != 1 {
		t.Fatalf("state = %+v, want found at 37 with one stage charged", st)
	}
	if l := st.Last.Lookup; l == nil || l.Outcome != chainread.LookupCandidate || l.Stage != 37 || l.Probe != ProbeMatched || l.TxID != lookupTestTxID {
		t.Fatalf("stop record lookup = %+v", st.Last.Lookup)
	}
	if r.Lookup == nil || r.Lookup.Probe != ProbeMatched {
		t.Fatalf("report lookup = %+v", r.Lookup)
	}
	// The table's hint is the worker's own observation, never the Indexer.
	if h := f.table(t).RecoveryHint(); h == nil || h.Source != "local_observation" || h.Stage != 37 || h.Authorizer != f.chain.authorizer {
		t.Fatalf("hint = %+v, want the local observation of stage 37", h)
	}
	if f.chain.lookups != 1 {
		t.Fatalf("lookups = %d, want 1", f.chain.lookups)
	}
}

// A miss costs one charged derivation and leaves no trace in the search
// order: the search that follows derives exactly what it would have without
// the lookup, and the miss stays in the table.
func TestLookupCandidateThatMissesLeavesTheSearchAsItWas(t *testing.T) {
	run := func(lookup bool) ([]uint64, *rotatingFixture) {
		f := newRotatingFixture(t)
		f.recovery().Configure(100, time.Hour)
		f.chain.authorizer = f.stageAddress(t, 5)
		if lookup {
			f.answerCandidate(30)
		}
		d := newDerivedOrder(t, f)
		opts := StageFillOptions{Horizon: 0, MaxDerivations: 4}
		for pass := 0; pass < 4; pass++ {
			if r := d.fill(opts); r.Resolved {
				break
			}
		}
		return d.order, f
	}
	without, _ := run(false)
	with, f := run(true)
	if len(with) == 0 || with[0] != 30 || !reflect.DeepEqual(with[1:], without) {
		t.Fatalf("derived with a missed candidate %v, without a lookup %v: want 30 then the same search", with, without)
	}
	// Stages 0 … 5 searched, and the miss.
	st := f.state()
	if st.Last == nil || st.Last.Reason != StopFound || *st.Last.Stage != 5 || st.Last.Charged != 7 {
		t.Fatalf("state = %+v, want found at 5 with the miss charged", st)
	}
	if l := st.Last.Lookup; l == nil || l.Probe != ProbeMissed || l.Stage != 30 {
		t.Fatalf("lookup = %+v, want a missed candidate 30", st.Last.Lookup)
	}
	if a, ok := f.table(t).Address(30); !ok || a != f.stageAddress(t, 30) || !f.table(t).Verified(30, a) {
		t.Fatal("the missed candidate is not in the table")
	}
	if h := f.table(t).RecoveryHint(); h == nil || h.Stage != 5 || h.Source != "local_observation" {
		t.Fatalf("hint = %+v, want the observation of stage 5", h)
	}
}

// Every outcome other than a candidate leaves the search exactly as with no
// Indexer: the same stages derived in the same order, the same charges and
// the same stop. The table has a backup hint, so the search's forward
// preference and its lower-gap probes both run.
// searchSummary is what a search did, without what differs between two
// fixtures (addresses, grant IDs, times).
type searchSummary struct {
	Active                       bool
	Charged                      uint64
	Kind                         GrantKind
	Reason                       string
	Stage                        *uint64
	AllowanceSpent, AllowanceMax uint64
	Suppressed                   bool
}

func summarize(st RecoveryState) searchSummary {
	out := searchSummary{AllowanceSpent: st.AllowanceSpent, AllowanceMax: st.AllowanceMax, Suppressed: !st.Suppressed.IsZero()}
	if g := st.Grant; g != nil {
		out.Active, out.Charged, out.Kind = true, g.Charged, g.Kind
	} else if l := st.Last; l != nil {
		out.Charged, out.Kind, out.Reason, out.Stage = l.Charged, l.Kind, l.Reason, l.Stage
	}
	return out
}

func TestLookupWithoutACandidateLeavesTheSearchIdentical(t *testing.T) {
	scenario := func(t *testing.T, answer func(f *rotatingFixture)) ([]uint64, searchSummary, []StageTableReport) {
		f := newRotatingFixture(t)
		f.recovery().Configure(60, time.Hour)
		round := uint64(500)
		if err := f.table(t).SetHint(stagetable.Hint{Stage: 40, Round: &round, Authorizer: f.stageAddress(t, 40), Source: "backup"}); err != nil {
			t.Fatal(err)
		}
		f.chain.authorizer = f.stageAddress(t, 70)
		answer(f)
		d := newDerivedOrder(t, f)
		var reports []StageTableReport
		for pass := 0; pass < 20; pass++ {
			r := d.fill(StageFillOptions{Horizon: 2, MaxDerivations: 5})
			reports = append(reports, r)
			if !r.Pending {
				break
			}
		}
		for i := range reports {
			reports[i].Account, reports[i].Authorizer, reports[i].Lookup = "", types.Address{}, nil
			reports[i].Recovery = RecoveryState{}
		}
		return d.order, summarize(f.state()), reports
	}
	baseOrder, baseState, baseReports := scenario(t, func(*rotatingFixture) {})
	if len(baseOrder) < 20 || baseState.Reason != StopFound || *baseState.Stage != 70 {
		t.Fatalf("baseline derived %v and ended %+v; want a long search that finds stage 70", baseOrder, baseState)
	}
	answers := map[string]func(f *rotatingFixture){}
	for _, o := range []chainread.LookupOutcome{chainread.LookupNoIndexer, chainread.LookupUnavailable, chainread.LookupNoOutgoingRekey, chainread.LookupNotCurrent, chainread.LookupNotAStageProgram, chainread.LookupWrongNetwork} {
		answers[string(o)] = func(f *rotatingFixture) { f.answerOutcome(o) }
	}
	answers["caller error"] = func(f *rotatingFixture) {
		f.chain.lookup = func(context.Context, types.Address, types.Address) (chainread.StageLookup, error) {
			return chainread.StageLookup{}, errors.New("caller mistake")
		}
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			order, state, reports := scenario(t, answer)
			if !reflect.DeepEqual(order, baseOrder) {
				t.Fatalf("derived %v, want the search without a lookup %v", order, baseOrder)
			}
			if !reflect.DeepEqual(state, baseState) {
				t.Fatalf("state %+v, want %+v", state, baseState)
			}
			if len(reports) != len(baseReports) {
				t.Fatalf("%d passes, want %d", len(reports), len(baseReports))
			}
			for i := range reports {
				if !reflect.DeepEqual(reports[i], baseReports[i]) {
					t.Fatalf("pass %d report %+v, want %+v", i, reports[i], baseReports[i])
				}
			}
		})
	}
}

// A candidate whose stage the table holds with a verified other address is
// not derived again; the search runs.
func TestLookupCandidateAtAVerifiedOtherAddressIsNotDerived(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.fillUntilSettled(t, StageFillOptions{Horizon: 3})
	f.chain.authorizer = f.stageAddress(t, 6)
	f.answerCandidate(2)
	d := newDerivedOrder(t, f)
	r := d.fill(StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if r.Err != nil || !r.Resolved || r.Stage != 6 {
		t.Fatalf("report = %+v", r)
	}
	if want := []uint64{4, 5, 6}; !reflect.DeepEqual(d.order[:3], want) {
		t.Fatalf("derived %v, want the search %v and no rederivation of stage 2", d.order, want)
	}
	st := f.state()
	if st.Last == nil || st.Last.Charged != 3 || st.Last.Lookup == nil || st.Last.Lookup.Probe != ProbeAlreadyCached {
		t.Fatalf("state = %+v, lookup %+v", st, st.Last.Lookup)
	}
}

// loadTableWith writes a table holding entries, as a restored or older
// table would, and reopens the store so the entries load unverified.
func (f *rotatingFixture) loadTableWith(t *testing.T, entries map[uint64]types.Address) {
	t.Helper()
	tb := f.table(t)
	for n, a := range entries {
		if _, err := tb.RecordDerived(n, []types.Address{a}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tb.Flush(); err != nil {
		t.Fatal(err)
	}
	f.tables = stagetable.NewStore(storepaths.NewPaths(f.root))
	f.svc.Rotating.Tables = f.tables
	for n, a := range entries {
		if f.table(t).Verified(n, a) {
			t.Fatalf("stage %d loaded verified", n)
		}
	}
}

// An unverified wrong address at the right stage does not discard the
// candidate: the stage is derived, the entry repaired, and the stage found
// after one derivation.
func TestLookupCandidateRepairsAnUnverifiedWrongEntry(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	stale := types.Address{0x5e, 31: 9}
	f.loadTableWith(t, map[uint64]types.Address{9: stale})
	f.chain.authorizer = f.stageAddress(t, 9)
	f.answerCandidate(9)
	r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if r.Err != nil || !r.Resolved || r.Stage != 9 {
		t.Fatalf("report = %+v", r)
	}
	st := f.state()
	if st.Last == nil || st.Last.Reason != StopFound || st.Last.Charged != 1 || st.Last.Lookup.Probe != ProbeMatched {
		t.Fatalf("state = %+v", st)
	}
	if a, _ := f.table(t).Address(9); a != f.chain.authorizer || !f.table(t).Verified(9, a) {
		t.Fatal("the stale entry was not repaired")
	}
}

// An unverified entry at a wrong candidate is derived once, confirmed or
// repaired, and the search runs.
func TestLookupWrongCandidateConfirmsOrRepairsAnUnverifiedEntry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry func(f *rotatingFixture) types.Address
	}{
		{"entry right", func(f *rotatingFixture) types.Address { return f.stageAddress(t, 9) }},
		{"entry wrong", func(*rotatingFixture) types.Address { return types.Address{0x5e, 31: 9} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRotatingFixture(t)
			f.recovery().Configure(100, time.Hour)
			f.loadTableWith(t, map[uint64]types.Address{9: tc.entry(f)})
			f.chain.authorizer = f.stageAddress(t, 2)
			f.answerCandidate(9)
			r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8})
			if r.Err != nil || !r.Resolved || r.Stage != 2 {
				t.Fatalf("report = %+v", r)
			}
			// The probe derives stage 9, and the search 0, 1 and 2.
			st := f.state()
			if st.Last == nil || st.Last.Charged != 4 || st.Last.Lookup.Probe != ProbeMissed {
				t.Fatalf("state = %+v, lookup %+v", st, st.Last.Lookup)
			}
			if a, _ := f.table(t).Address(9); a != f.stageAddress(t, 9) || !f.table(t).Verified(9, a) {
				t.Fatal("stage 9 was not confirmed or repaired")
			}
			for _, n := range []uint64{0, 1, 2} {
				if _, ok := f.table(t).Address(n); !ok {
					t.Fatalf("the search did not derive stage %d", n)
				}
			}
		})
	}
}

func TestLookupRunsOncePerGrant(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 12)
	f.answerCandidate(40)
	opts := StageFillOptions{Horizon: 0, MaxDerivations: 3}
	first := f.fill(t, opts)
	if !first.Pending || first.Lookup == nil || first.Lookup.Probe != ProbeMissed {
		t.Fatalf("first pass = %+v, lookup %+v", first, first.Lookup)
	}
	grant := f.state().Grant
	second := f.fill(t, opts)
	if second.Lookup != nil || f.chain.lookups != 1 {
		t.Fatalf("second pass of grant %d looked up again: %+v, lookups %d", grant.ID, second.Lookup, f.chain.lookups)
	}
	// The grant still reports its lookup while it searches.
	if st := f.state(); st.Grant == nil || st.Grant.ID != grant.ID || st.Grant.Lookup == nil || st.Grant.Lookup.Probe != ProbeMissed {
		t.Fatalf("state = %+v", st)
	}
	r := f.fillUntilSettled(t, opts)
	if !r.Resolved || r.Stage != 12 || f.chain.lookups != 1 {
		t.Fatalf("report = %+v after %d lookups", r, f.chain.lookups)
	}
}

func TestLookupRunsAgainForTheGrantOfANewAuthorizer(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
	f.answerOutcome(chainread.LookupNotCurrent)
	opts := StageFillOptions{Horizon: 0, MaxDerivations: 2}
	f.fill(t, opts)
	first := f.state().Grant
	if first == nil || first.Lookup == nil || first.Lookup.Outcome != chainread.LookupNotCurrent {
		t.Fatalf("first grant = %+v", first)
	}
	f.chain.authorizer = f.stageAddress(t, 20)
	f.answerCandidate(20)
	r := f.fill(t, opts)
	if !r.Resolved || r.Stage != 20 || f.chain.lookups != 2 {
		t.Fatalf("report = %+v after %d lookups", r, f.chain.lookups)
	}
	st := f.state()
	if st.Last == nil || st.Last.GrantID == first.ID || st.Last.Charged != 1 || st.Last.Lookup.Probe != ProbeMatched {
		t.Fatalf("state = %+v", st)
	}
}

func TestOperatorGrantWithAStageHintDoesNotLookUp(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 10)
	f.answerCandidate(10)
	hint := uint64(9)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), &hint, 3, 100, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fillUntilSettled(t, StageFillOptions{Horizon: 0, Batch: 64})
	if !r.Resolved || r.Stage != 10 || f.chain.lookups != 0 {
		t.Fatalf("report = %+v after %d lookups, want the hint's probes alone", r, f.chain.lookups)
	}
	// Probes 9 and 10.
	if st := f.state(); st.Last == nil || st.Last.Charged != 2 || st.Last.Lookup != nil {
		t.Fatalf("state = %+v", st)
	}
}

func TestOperatorGrantWithoutAStageHintLooksUpFirst(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 50)
	f.answerCandidate(50)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 100, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if !r.Resolved || r.Stage != 50 || f.chain.lookups != 1 {
		t.Fatalf("report = %+v after %d lookups", r, f.chain.lookups)
	}
	if st := f.state(); st.Last == nil || st.Last.Kind != GrantOperator || st.Last.Charged != 1 || st.Last.Lookup.Probe != ProbeMatched || st.AllowanceSpent != 0 {
		t.Fatalf("state = %+v", st)
	}
}

func TestNoGrantNoLookup(t *testing.T) {
	t.Run("automatic recovery disabled", func(t *testing.T) {
		f := newRotatingFixture(t)
		f.recovery().Configure(0, time.Hour)
		f.chain.authorizer = f.stageAddress(t, 3)
		f.answerCandidate(3)
		if r := f.fill(t, StageFillOptions{Horizon: 0}); r.Resolved || f.chain.lookups != 0 {
			t.Fatalf("report = %+v after %d lookups", r, f.chain.lookups)
		}
	})
	t.Run("allowance exhausted and authorizer suppressed", func(t *testing.T) {
		f := newRotatingFixture(t)
		f.recovery().Configure(2, time.Hour)
		f.chain.authorizer = types.Address{0xde, 0xad, 31: 1}
		f.answerOutcome(chainread.LookupNoOutgoingRekey)
		opts := StageFillOptions{Horizon: 0, MaxDerivations: 8}
		f.fill(t, opts)
		if st := f.state(); st.Last == nil || st.Last.Reason != StopAllowanceExhausted || f.chain.lookups != 1 {
			t.Fatalf("state = %+v after %d lookups", st, f.chain.lookups)
		}
		// Suppressed for this authorizer: no grant, no lookup.
		f.fill(t, opts)
		// Exhausted for another authorizer too.
		f.chain.authorizer = types.Address{0xbe, 0xef, 31: 2}
		f.fill(t, opts)
		if f.chain.lookups != 1 {
			t.Fatalf("lookups = %d, want only the first grant's", f.chain.lookups)
		}
	})
}

func TestLookupCandidateMatchesOnAGrantsLastStage(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(1, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 8)
	f.answerCandidate(8)
	r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if !r.Resolved || r.Stage != 8 {
		t.Fatalf("report = %+v", r)
	}
	if st := f.state(); st.Last == nil || st.Last.Reason != StopFound || st.Last.Charged != 1 || st.AllowanceSpent != 1 {
		t.Fatalf("state = %+v", st)
	}
}

// An automatic grant with one stage left spends it on a missed candidate:
// it stops as allowance exhausted, the search derives nothing, and the
// authorizer is suppressed until the next unlock.
func TestLookupMissOnAnAutomaticGrantsLastStageExhaustsTheAllowance(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(1, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 3)
	f.answerCandidate(30)
	opts := StageFillOptions{Horizon: 0, MaxDerivations: 8}
	r := f.fill(t, opts)
	if r.Resolved || r.Pending || r.Scanned != 1 {
		t.Fatalf("report = %+v, want only the miss derived", r)
	}
	if _, ok := f.table(t).Address(30); !ok {
		t.Fatal("the miss is not in the table")
	}
	st := f.state()
	if st.Grant != nil || st.Last == nil || st.Last.Reason != StopAllowanceExhausted || st.Last.Charged != 1 || st.Suppressed != f.chain.authorizer {
		t.Fatalf("state = %+v", st)
	}
	if st.Last.Lookup == nil || st.Last.Lookup.Probe != ProbeMissed {
		t.Fatalf("stop record lookup = %+v", st.Last.Lookup)
	}
	f.fill(t, opts)
	if f.chain.lookups != 1 || f.state().Grant != nil {
		t.Fatalf("suppressed authorizer looked up again: %d", f.chain.lookups)
	}
	// The next unlock: a fresh allowance, a new grant, a new lookup.
	f.lockGen++
	f.recovery().Configure(100, time.Hour)
	f.answerCandidate(3)
	if r := f.fill(t, opts); !r.Resolved || r.Stage != 3 || f.chain.lookups != 2 {
		t.Fatalf("after unlock: %+v after %d lookups", r, f.chain.lookups)
	}
}

func TestLookupMissOnAnOperatorGrantsLastStageExhaustsItsBudget(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(0, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 3)
	f.answerCandidate(30)
	if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), nil, 0, 1, 0); err != nil {
		t.Fatal(err)
	}
	r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if r.Resolved || r.Pending || r.Scanned != 1 {
		t.Fatalf("report = %+v", r)
	}
	if st := f.state(); st.Last == nil || st.Last.Reason != StopBudgetExhausted || st.Last.Charged != 1 || st.Last.Lookup.Probe != ProbeMissed {
		t.Fatalf("state = %+v", st)
	}
}

// A missed candidate's derivation counts in the grant's active time: a grant
// whose time it uses up stops with nothing more derived.
func TestLookupMissCountsInTheGrantsActiveTime(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 3)
	f.answerCandidate(30)
	r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 1})
	if !r.Pending {
		t.Fatalf("report = %+v", r)
	}
	if g := f.state().Grant; g == nil || g.Charged != 1 || g.Active <= 0 {
		t.Fatalf("grant = %+v, want the miss charged with its time", g)
	}

	f = newRotatingFixture(t)
	f.recovery().Configure(100, time.Nanosecond)
	f.chain.authorizer = f.stageAddress(t, 3)
	f.answerCandidate(30)
	r = f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if r.Resolved || r.Scanned != 1 {
		t.Fatalf("report = %+v, want the miss alone", r)
	}
	if st := f.state(); st.Last == nil || st.Last.Reason != StopTimedOut || st.Last.Charged != 1 {
		t.Fatalf("state = %+v", st)
	}
}

// A lock cancels the pass's context during the lookup and ends the session:
// nothing is derived or charged, and the pass is cut as one cut at the chain
// read is.
func TestLockDuringTheLookupDerivesNothing(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 6)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.chain.lookup = func(ctx context.Context, _, _ types.Address) (chainread.StageLookup, error) {
		f.lockGen++
		cancel()
		<-ctx.Done()
		return chainread.StageLookup{Outcome: chainread.LookupUnavailable, Reason: "the lookup was cancelled"}, nil
	}
	reports, cut := f.svc.FillStageTables(ctx, f.session, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if len(reports) != 1 || reports[0].Resolved || reports[0].Pending || cut && ctx.Err() == nil {
		t.Fatalf("reports = %+v, cut %v", reports, cut)
	}
	if f.table(t).Len() != 0 {
		t.Fatalf("table len = %d after a pass the lock ended during the lookup", f.table(t).Len())
	}
	if st := f.state(); st.Grant != nil || st.AllowanceSpent != 0 {
		t.Fatalf("the ended session left state: %+v", st)
	}
}

// A lock that refuses the probe's key use cuts the pass: the probe does not
// run, the search derives nothing, and FillStageTables reports the cut so
// the worker publishes nothing.
func TestLockDuringTheProbeCutsThePass(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 6)
	f.chain.lookup = func(context.Context, types.Address, types.Address) (chainread.StageLookup, error) {
		// The lock's first step: key uses are refused from here on.
		f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
			refused, stop := context.WithCancel(ctx)
			stop()
			return refused, func() {}
		}
		return chainread.StageLookup{Outcome: chainread.LookupCandidate, Stage: 6}, nil
	}
	reports, cut := f.svc.FillStageTables(context.Background(), f.session, StageFillOptions{Horizon: 0, MaxDerivations: 8})
	if !cut || len(reports) != 1 || reports[0].Resolved {
		t.Fatalf("reports = %+v, cut %v; want the pass cut", reports, cut)
	}
	if f.table(t).Len() != 0 {
		t.Fatalf("table len = %d after the probe was refused", f.table(t).Len())
	}
	if l := reports[0].Lookup; l == nil || l.Outcome != chainread.LookupCandidate || l.Probe != "" {
		t.Fatalf("lookup = %+v, want a candidate whose probe did not run", l)
	}
	if st := f.state(); st.Grant == nil || st.Grant.Charged != 0 {
		t.Fatalf("state = %+v, want nothing charged", st)
	}
}

// The lookup reads the chain only: it is asked with the account, the
// authorizer the worker read from its own algod, and the key's genesis hash.
func TestLookupIsAskedForTheObservedAuthorizer(t *testing.T) {
	f := newRotatingFixture(t)
	f.recovery().Configure(100, time.Hour)
	f.chain.authorizer = f.stageAddress(t, 4)
	var gotAccount, gotAuthorizer types.Address
	f.chain.lookup = func(_ context.Context, account, authorizer types.Address) (chainread.StageLookup, error) {
		gotAccount, gotAuthorizer = account, authorizer
		return chainread.StageLookup{Outcome: chainread.LookupCandidate, Stage: 4}, nil
	}
	if r := f.fill(t, StageFillOptions{Horizon: 0, MaxDerivations: 8}); !r.Resolved {
		t.Fatalf("report = %+v", r)
	}
	if gotAccount != f.account || gotAuthorizer != f.chain.authorizer {
		t.Fatalf("lookup asked for %s / %s", gotAccount, gotAuthorizer)
	}
}
