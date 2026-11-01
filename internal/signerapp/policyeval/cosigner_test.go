// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeval

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

func cosignerPolicy(t *testing.T, sparse string) *policy.Config {
	t.Helper()
	return policytest.Compile(t, noderole.RoleCosigner, policy.DefaultKey, sparse)
}

func onNetwork(t *testing.T, txn types.Transaction, encoded string) types.Transaction {
	t.Helper()
	hash, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	copy(txn.GenesisHash[:], hash)
	return txn
}

const anyRoute = `{"transfer_policy": {"routes": [{"id": "any", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]}]}}`

func TestCosignerApprovesOrRejectsAcrossSparseTargets(t *testing.T) {
	strict := cosignerPolicy(t, "")
	open := cosignerPolicy(t, anyRoute)
	group := []types.Transaction{
		onNetwork(t, pay(1, 2, 1), apconfig.AlgorandTestnetGenesisHash),
		onNetwork(t, pay(3, 4, 1), apconfig.AlgorandTestnetGenesisHash),
		onNetwork(t, pay(5, 6, 1), apconfig.AlgorandTestnetGenesisHash),
	}

	verdict, err := Evaluate(Input{Role: RoleCosigner, Group: group, Slots: []Slot{{Index: 0, Policy: open}, {Index: 2, Policy: open}}})
	if err != nil || verdict.Outcome != Approve || verdict.RuleID != "" {
		t.Fatalf("Evaluate(open) = %+v, %v; want Approve", verdict, err)
	}

	verdict, err = Evaluate(Input{Role: RoleCosigner, Group: group, Slots: []Slot{{Index: 0, Policy: strict}, {Index: 2, Policy: strict}}})
	if err != nil || verdict.Outcome != Reject || len(verdict.Violations) != 2 {
		t.Fatalf("Evaluate(strict) = %+v, %v; want two violations", verdict, err)
	}
	if verdict.Violations[0].TxnIndex != 0 || verdict.Violations[1].TxnIndex != 2 {
		t.Fatalf("violation indices = %d, %d; want 0, 2", verdict.Violations[0].TxnIndex, verdict.Violations[1].TxnIndex)
	}
}

func TestCosignerKnownNetworksComeFromTheInput(t *testing.T) {
	const custom = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{custom: "devnet-x"})
	if err != nil {
		t.Fatal(err)
	}
	// The node compiles its policies with the same mapping it checks
	// networks with, so routing knows the custom network too.
	open := cosignerPolicy(t, anyRoute)
	open.GenesisHashResolver = networks
	group := []types.Transaction{onNetwork(t, pay(1, 2, 1), custom)}
	in := Input{Role: RoleCosigner, Group: group, Slots: []Slot{{Index: 0, Policy: open}}}

	verdict, err := Evaluate(in)
	if err != nil || verdict.Outcome != Reject || verdict.Violations[0].RuleID != policy.UnknownGenesisHashRuleID {
		t.Fatalf("built-in networks only: %+v, %v; want the unknown-network violation", verdict, err)
	}
	in.Networks = networks
	if verdict, err := Evaluate(in); err != nil || verdict.Outcome != Approve {
		t.Fatalf("with the node's mapping: %+v, %v; want Approve", verdict, err)
	}
}

func TestCosignerReviewIsARejection(t *testing.T) {
	// A cosigner document cannot hold a review rule; a config that does must
	// still never yield a review verdict.
	cfg := cosignerPolicy(t, anyRoute)
	cfg.TransactionTypes = policy.TransactionTypesV1{policy.TransactionTypeWildcard: policy.TransactionTypeAllow, "pay": policy.TransactionTypeReview}
	group := []types.Transaction{onNetwork(t, pay(1, 2, 1), apconfig.AlgorandTestnetGenesisHash)}
	verdict, err := Evaluate(Input{Role: RoleCosigner, Group: group, Slots: []Slot{{Index: 0, Policy: cfg}}})
	if err != nil || verdict.Outcome != Reject {
		t.Fatalf("Evaluate() = %+v, %v; want Reject", verdict, err)
	}
}

func TestCosignerMissingPolicyIsAnError(t *testing.T) {
	strict := cosignerPolicy(t, "")
	group := []types.Transaction{
		onNetwork(t, pay(1, 2, 1), apconfig.AlgorandTestnetGenesisHash),
		onNetwork(t, pay(3, 4, 1), apconfig.AlgorandTestnetGenesisHash),
	}
	verdict, err := Evaluate(Input{Role: RoleCosigner, Group: group, Slots: []Slot{{Index: 0, Policy: strict}, {Index: 1}}})
	if !errors.Is(err, ErrPolicyNotLoaded) || verdict.Violations != nil {
		t.Fatalf("Evaluate() = %+v, %v; want ErrPolicyNotLoaded and no violations", verdict, err)
	}
}

func TestCosignerIgnoresPlanAndSelfNoOpApproval(t *testing.T) {
	// Approve on a cosigner means the policy checks passed; the client's
	// self no-op rule and plan facts play no part.
	group := []types.Transaction{onNetwork(t, pay(1, 1, 0), apconfig.AlgorandTestnetGenesisHash)}
	in := Input{Role: RoleCosigner, Group: group, Slots: []Slot{{Index: 0, Policy: cosignerPolicy(t, "")}}, Plan: &PlanFacts{RequestCount: 1, AuthAddressPresent: true}}
	verdict, err := Evaluate(in)
	if err != nil || verdict.Outcome != Reject || verdict.RuleID != "" {
		t.Fatalf("Evaluate() = %+v, %v; want a route-miss Reject", verdict, err)
	}
}
