// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestCategorizeRequests_AllowsForeign(t *testing.T) {
	_, foreign, err := categorizeRequests([]signerapi.SignRequest{{TxnBytesHex: "deadbeef"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(foreign) != 1 {
		t.Fatalf("expected 1 foreign request, got %d", len(foreign))
	}
}

func TestValidateKnownNetwork_AcceptsKnownNetworks(t *testing.T) {
	for _, hash := range []string{
		apconfig.AlgorandMainnetGenesisHash,
		apconfig.AlgorandTestnetGenesisHash,
		apconfig.AlgorandBetanetGenesisHash,
	} {
		err := validateKnownNetwork([]types.Transaction{
			{Header: types.Header{GenesisHash: testGenesisDigest(t, hash)}},
		}, apconfig.DefaultGenesisHashNetworkResolver())
		if err != nil {
			t.Errorf("validateKnownNetwork(%q) = %v, want nil", hash, err)
		}
	}
}

func TestValidateKnownNetwork_RejectsUnknownGenesisHash(t *testing.T) {
	for _, hash := range []types.Digest{{}, {1, 2, 3}, {9, 9, 9}} {
		err := validateKnownNetwork([]types.Transaction{
			{Header: types.Header{GenesisHash: hash}},
		}, apconfig.DefaultGenesisHashNetworkResolver())
		if err == nil {
			t.Errorf("validateKnownNetwork(%x) = nil, want error", hash[:])
		}
	}
}

func TestValidateKnownNetwork_RejectsIfAnyTxnHasUnknownNetwork(t *testing.T) {
	err := validateKnownNetwork([]types.Transaction{
		{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}},
		{Header: types.Header{GenesisHash: types.Digest{}}},
	}, apconfig.DefaultGenesisHashNetworkResolver())
	if err == nil {
		t.Fatal("expected error for mixed known/unknown genesis hashes")
	}
	if !strings.Contains(err.Error(), "transaction 2") {
		t.Fatalf("error should reference transaction 2, got: %v", err)
	}
}

func testGenesisDigest(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}

// planFeeFingerprint is everything a plan's fee planning decides: each
// transaction as encoded, the fee info and the mutation report.
func planFeeFingerprint(t *testing.T, plan *PlanResult, originalCount int) string {
	t.Helper()
	var b strings.Builder
	for i, txn := range plan.AllTxns {
		fmt.Fprintf(&b, "txn %d fee %d: %x\n", i, txn.Fee, sha256.Sum256(txnutil.EncodeWithPrefix(txn)))
	}
	fmt.Fprintf(&b, "dummies %d lsig %v regroup %v pregrouped %v\n", plan.DummiesNeeded, plan.LsigIndices, plan.NeedsRegroup, plan.IsPreGrouped)
	fmt.Fprintf(&b, "fee info %+v\n", plan.FeeInfo)
	fmt.Fprintf(&b, "mutations %+v\n", *BuildMutationReport(plan, originalCount))
	return b.String()
}

// A group whose native Falcon and LogicSig slots both draw charges, and whose
// LogicSig slot needs resource dummies, is planned to the same bytes, fee
// info and mutation report by the daemon's planner and by a bare one.
func TestPlanGroupFeePlanningIsUnchanged(t *testing.T) {
	genesisHash := types.Digest{5}
	native, lsig := types.Address{8}.String(), types.Address{9}.String()
	profile := lsigresource.Profile{
		ProgramBytes: 4_500,
		Default:      &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 79_999},
	}
	deps := stubPlannerDeps{
		keyTypes: map[string]string{native: nativefalcon.KeyType, lsig: "aplane.falcon1024.v1"},
		keyMetadata: map[string]PlannerKeyMetadata{lsig: {
			Category: "dsa_lsig", PublicKeyHex: "aabb", LogicSigResources: &profile,
		}},
	}
	payment := func(sender types.Address, amount uint64) string {
		return txnutil.EncodeWithPrefixHex(types.Transaction{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: sender, Fee: 1_000, FirstValid: 1, LastValid: 2, GenesisHash: genesisHash},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: types.MicroAlgos(amount)},
		})
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: native, TxnBytesHex: payment(types.Address{8}, 1)},
		{AuthAddress: lsig, TxnBytesHex: payment(types.Address{9}, 2)},
	}}
	// Recorded from the planner before its injected group builder and
	// resource solver were removed.
	const want = `txn 0 fee 6000: 3d45a377a2e3f32b86d1e048a3893198eaf74aadf303c41343bdc80c241acf36
txn 1 fee 1000: 2f7c44c684fa35e0ff28903352b847d245d3eb24b8891920372898c25221bea4
txn 2 fee 0: b94428046a3ac53ccc682464f15294584083944857f88d8b52b24764ce6b0a10
txn 3 fee 0: 065345277fed07b98f8205c93ff72b3a8fda0fde214480fe5a56bb8c16d665d1
txn 4 fee 0: 55e4516bb3b3b8ee0964b855aad668c1eadf2e4f1004f7385a26926d4495c2f1
dummies 3 lsig [1] regroup true pregrouped false
fee info {TotalFees:5000 LSigCount:1 FeeIndices:[0] ProgramFeeContribution:0 NativePQFeeContribution:2000}
mutations {DummiesAdded:3 GroupIDChanged:true FeesModified:[0] TotalFeesDelta:5000 OriginalCount:2 FinalCount:5 PassthroughCount:0 ForeignCount:0 Reason:lsig_budget+native_pq_fee}
`
	for name, planner := range map[string]*Planner{
		"daemon": NewPlanner(deps, PlannerOptions{GenesisHashResolver: feeTestResolver(t, genesisHash)}),
		"bare":   {Snapshot: deps.Snapshot, GenesisHashResolver: feeTestResolver(t, genesisHash)},
	} {
		if name == "bare" {
			planner.VerifySignableKeys = NewPlanner(deps, PlannerOptions{}).VerifySignableKeys
		}
		plan, err := planner.PlanGroup(req)
		if err != nil {
			t.Fatalf("%s PlanGroup() error = %v", name, err)
		}
		if got := planFeeFingerprint(t, plan, len(req.Requests)); got != want {
			t.Fatalf("%s plan =\n%s\nwant\n%s", name, got, want)
		}
	}
}

// validateNetworkParams refuses a second network first, then a group whose
// validity windows do not overlap, and prints the window it accepted.
func TestValidateNetworkParamsRefusalsAndWindow(t *testing.T) {
	at := func(genesis byte, first, last uint64) types.Transaction {
		return types.Transaction{Header: types.Header{GenesisHash: types.Digest{genesis}, FirstValid: types.Round(first), LastValid: types.Round(last)}}
	}
	cases := []struct {
		name    string
		txns    []types.Transaction
		want    string
		console string
	}{
		{name: "window", txns: []types.Transaction{at(1, 5, 30), at(1, 10, 20), at(1, 7, 25)}, console: "[GROUP] Network params validated, validity window: rounds 10-20\n"},
		{name: "second network before a disjoint window", txns: []types.Transaction{at(1, 5, 6), at(2, 10, 20)}, want: "transaction 2 has different genesis hash - all transactions must target the same network"},
		{name: "disjoint", txns: []types.Transaction{at(1, 5, 6), at(1, 10, 20)}, want: "transaction validity windows do not overlap (earliest LastValid: 6, latest FirstValid: 10) - group would never be valid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			err := validateNetworkParams(tc.txns, &stringConsole{b: &b})
			if tc.want == "" {
				if err != nil || b.String() != tc.console {
					t.Fatalf("err = %v console %q, want none and %q", err, b.String(), tc.console)
				}
				return
			}
			if err == nil || err.Kind != ErrorBadRequest || err.Message != tc.want {
				t.Fatalf("err = %#v, want %q", err, tc.want)
			}
		})
	}
}
