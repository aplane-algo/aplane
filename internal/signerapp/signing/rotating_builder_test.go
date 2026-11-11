// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// previousRotatingGroup is the private builder the rotating flow used before
// it moved onto the shared group builder. It is kept here only to pin that
// the move changed no single-spend group.
func previousRotatingGroup(t *testing.T, txn types.Transaction, profile *lsigresource.Profile) []types.Transaction {
	t.Helper()
	txn.Group = types.Digest{}
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	usage, err := profile.UsageForPath(lsigresource.PathDefault)
	if err != nil {
		t.Fatal(err)
	}
	resourcePlan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs:        []lsigresource.Usage{usage},
		Dummy:            lsigresource.Usage{ProgramBytes: uint64(len(coresigning.EmbeddedDummyTealTok)), MaxOpcodeCost: coresigning.DummyOpcodeCost},
	})
	if err != nil {
		t.Fatal(err)
	}
	dummies := int(resourcePlan.DummyCount)
	allTxns, _, _, _, buildErr := buildFinalGroupWithoutFees(nil, []types.Transaction{txn}, dummies, false)
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	if _, feeErr := applyGroupFees(allTxns, []authorizationBudget{{mutable: true}}, resourcePlan, dummies, []int{0}, false); feeErr != nil {
		t.Fatal(feeErr)
	}
	if len(allTxns) > 1 {
		for i := range allTxns {
			allTxns[i].Group = types.Digest{}
		}
		gid, gidErr := algocrypto.ComputeGroupID(allTxns)
		if gidErr != nil {
			t.Fatal(gidErr)
		}
		for i := range allTxns {
			allTxns[i].Group = gid
		}
	}
	return allTxns
}

// TestRotatingBuilderMatchesThePreviousBuilder checks, for every rotating
// key type and a spread of user fees, that the shared builder produces the
// exact group the private one did, that the signer's charge is the same at
// every fee and lands on the spend on top of the user's fee, and that
// rebuilding a prepared spend reproduces the group, which is what sign
// relies on. A spend below the ordinary fee floor is refused, as it always
// was, and so is a presented spend paying less than the charge.
func TestRotatingBuilderMatchesThePreviousBuilder(t *testing.T) {
	for _, kind := range rotatingTestTypes {
		t.Run(kind.keyType, func(t *testing.T) {
			f, _ := newSigningFixtureFor(t, kind)
			account := f.account.String()
			profile := f.svc.Planner.Snapshot().KeyMetadata[account].LogicSigResources
			if profile == nil {
				t.Fatal("fixture has no resource profile for the rotating account")
			}
			underpaid := f.spend(1000, 1100)
			underpaid.Fee = 0
			if _, err := f.svc.Planner.buildRotatingGroup(account, underpaid, profile); err == nil || !strings.Contains(err.Message, "below the v42 ordinary transaction requirement") {
				t.Fatalf("a spend paying no fee: err = %v, want the ordinary fee floor refusal", err)
			}
			var charge uint64
			for n, fee := range []uint64{1000, 5000, 250_000} {
				spend := f.spend(1000, 1100)
				spend.Fee = types.MicroAlgos(fee)
				spend.RekeyTo = types.Address{0x51}
				want := previousRotatingGroup(t, spend, profile)
				plan, err := f.svc.Planner.buildRotatingGroup(account, spend, profile)
				if err != nil {
					t.Fatal(err)
				}
				if len(plan.AllTxns) != len(want) || len(want) != kind.dummies+1 {
					t.Fatalf("fee %d: group has %d transactions, previous builder %d, want %d dummies", fee, len(plan.AllTxns), len(want), kind.dummies)
				}
				for i := range want {
					if !bytes.Equal(txnutil.EncodeWithPrefix(plan.AllTxns[i]), txnutil.EncodeWithPrefix(want[i])) {
						t.Fatalf("fee %d: transaction %d differs from the previous builder's", fee, i+1)
					}
				}
				if n == 0 {
					charge = plan.FeeInfo.TotalFees
					if charge == 0 {
						t.Fatalf("fee %d: the rotating spend carries no signer charge", fee)
					}
				}
				if plan.FeeInfo.TotalFees != charge || uint64(plan.AllTxns[0].Fee) != fee+charge {
					t.Fatalf("fee %d: charge %d and spend fee %d, want charge %d on top of the user's fee", fee, plan.FeeInfo.TotalFees, plan.AllTxns[0].Fee, charge)
				}
				again, err := f.svc.Planner.rebuildPreparedRotatingGroup(account, plan.AllTxns[0], profile)
				if err != nil {
					t.Fatal(err)
				}
				for i := range want {
					if !bytes.Equal(txnutil.EncodeWithPrefix(again.AllTxns[i]), txnutil.EncodeWithPrefix(plan.AllTxns[i])) {
						t.Fatalf("fee %d: rebuilding the prepared spend changed transaction %d", fee, i+1)
					}
				}
			}
			// A presented spend paying less than the charge cannot have come
			// from prepare. Below the ordinary floor the builder refuses it
			// first; above it, the charge check does.
			short := f.spend(1000, 1100)
			short.RekeyTo = types.Address{0x51}
			short.Fee = types.MicroAlgos(charge - 1)
			_, err := f.svc.Planner.rebuildPreparedRotatingGroup(account, short, profile)
			if err == nil || (charge > 1001 && !strings.Contains(err.Message, "authorization charge")) {
				t.Fatalf("a presented spend paying %d below the charge %d: err = %v, want a refusal", short.Fee, charge, err)
			}
		})
	}
}
