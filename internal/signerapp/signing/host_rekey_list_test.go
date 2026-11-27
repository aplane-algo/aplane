// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	listTestPrivateKey = bytes.Repeat([]byte{0x66}, 64)
	listTestTarget     = types.Address{0x51}
	listTestOther      = types.Address{0x52}
)

// listTestAccount is an "only these" account with listTestTarget on its list,
// as the signer's snapshot holds it.
func listTestAccount(t *testing.T) (*hostmeta.Metadata, map[string]string) {
	t.Helper()
	params := map[string]string{hostmeta.RekeyListEntriesParameter: listTestTarget.String()}
	list, err := rekeylist.FromSpendingKey(listTestPrivateKey, []types.Address{listTestTarget})
	if err != nil {
		t.Fatal(err)
	}
	root := list.Root()
	list.Zero()
	layout := hostmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}
	slots := append(hostmeta.BaseArgumentLayout(layout), hostmeta.ArgumentSlot{
		Index: 1, Name: "rekey_list_proof", Source: hostmeta.ArgSourceDerived, MaxSize: hostmeta.RekeyListProofSize,
		Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgForbidden, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgRequired},
	})
	metadata := &hostmeta.Metadata{
		Contract: hostmeta.BoundedContract, BaseSignatureArgLayout: layout, ArgumentLayout: slots,
		Bounds: &hostmeta.Bounds{SpendEffects: []string{"pay"}, MaxFee: new(uint64(5_000)), Layer3Policy: hostmeta.Layer3PolicyCustom}, Rekey: hostmeta.RekeyRefused,
		RekeyList: &hostmeta.RekeyList{Contract: hostmeta.RekeyListContractV1, Depth: rekeylist.Depth, RootHex: hex.EncodeToString(root[:])},
		DerivedArgs: []hostmeta.DerivedArg{{
			Name: "rekey_list_proof", Kind: hostmeta.DerivedArgRekeyListProof,
			Parameter: hostmeta.RekeyListEntriesParameter, MaxSize: hostmeta.RekeyListProofSize,
		}},
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("list metadata invalid: %v", err)
	}
	return metadata, params
}

func listTestRekey(target types.Address) types.Transaction {
	txn := testBoundedRekey()
	txn.RekeyTo = target
	return txn
}

// The planner sends a rekey to a listed target down the listed path, and refuses
// any other rekey with a named error before anything is signed.
func TestPlannerTakesTheListedPathOnlyForAListedTarget(t *testing.T) {
	metadata, params := listTestAccount(t)
	snapshot := PlannerRuntimeSnapshot{KeyMetadata: map[string]PlannerKeyMetadata{
		"ACCOUNT": {PublicKeyHex: "01", BaseKeyType: "aplane.falcon1024.v1", Parameters: params, Host: metadata},
	}}
	request := []signerapi.SignRequest{{AuthAddress: "ACCOUNT"}}
	items, err := resolveHostPlanItems(snapshot, request, []types.Transaction{listTestRekey(listTestTarget)}, nil, nil)
	if err != nil {
		t.Fatalf("listed target: %+v", err)
	}
	if items[0].Path != hostPathListedRekey || !items[0].ListedRekeyTargets[listTestTarget.String()] {
		t.Fatalf("item = %+v", items[0])
	}
	_, err = resolveHostPlanItems(snapshot, request, []types.Transaction{listTestRekey(listTestOther)}, nil, nil)
	if err == nil || err.Kind != ErrorRekeyTargetNotListed || err.Code() != signerapi.ErrCodeRekeyTargetNotListed ||
		!strings.Contains(err.Message, "not on this account's rekey-to list") {
		t.Fatalf("unlisted target: error = %+v", err)
	}
	if path, err := logicSigAuthorizationPath(hostPathListedRekey); err != nil || path != lsigresource.PathListedRekey {
		t.Fatalf("resource path = %v, %v", path, err)
	}
}

// The proof is the one the account's own list gives for the target, and the
// stored root must match the list the signer rebuilds.
func TestListedRekeyDerivesTheListProof(t *testing.T) {
	metadata, params := listTestAccount(t)
	key := &coresigning.KeyMaterial{Value: &coresigning.LsigKeyMaterial{PrivateKey: listTestPrivateKey}, Parameters: params}
	values, err := hostDerivedArgs(listTestRekey(listTestTarget), key, metadata, hostPathListedRekey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := hex.DecodeString(metadata.RekeyList.RootHex)
	var root32 [32]byte
	copy(root32[:], root)
	proofName := metadata.DerivedArgs[0].Name
	if len(values) != 1 || !rekeylist.Verify(listTestTarget, values[proofName], root32) {
		t.Fatalf("derived proof does not verify: %x", values)
	}
	tampered := hostmeta.Clone(metadata)
	tampered.RekeyList.RootHex = strings.Repeat("00", 32)
	if _, err := hostDerivedArgs(listTestRekey(listTestTarget), key, tampered, hostPathListedRekey); err == nil || !strings.Contains(err.Message, "does not match the account's stored root") {
		t.Fatalf("mismatched root: error = %+v", err)
	}
	if values, err := hostDerivedArgs(testBoundedPayment(), key, metadata, hostPathPureSpend); err != nil || len(values[proofName]) != 0 {
		t.Fatalf("a spend carries a list proof: %x, %+v", values, err)
	}
}

// A listed rekey hands the account over, so the warning says so, and says when
// the target leaves this signer's custody.
func TestListedRekeyWarningNamesTheHandover(t *testing.T) {
	listed := map[string]bool{listTestTarget.String(): true}
	unheld := txnreview.Findings(listTestRekey(listTestTarget), txnreview.FindingContext{ListedRekeyTargets: listed})
	if len(unheld) != 1 || !strings.Contains(unheld[0].Message, "rekey-to list") || !strings.Contains(unheld[0].Message, "LEAVES THIS SIGNER'S CUSTODY") {
		t.Fatalf("unheld listed target warning = %+v", unheld)
	}
	held := txnreview.Findings(listTestRekey(listTestTarget), txnreview.FindingContext{
		ListedRekeyTargets: listed, KnownAddresses: listed,
	})
	if len(held) != 1 || !strings.Contains(held[0].Message, txnreview.RekeyHeldText) {
		t.Fatalf("held listed target warning = %+v", held)
	}
}

// A listed rekey is a bounded rekey, so the signer forces its review: the self
// no-op rule, which would approve the same 0-ALGO self-payment without one,
// never approves it.
func TestListedRekeyIsForcedToReview(t *testing.T) {
	metadata, params := listTestAccount(t)
	snapshot := PlannerRuntimeSnapshot{KeyMetadata: map[string]PlannerKeyMetadata{
		"ACCOUNT": {PublicKeyHex: "01", BaseKeyType: "aplane.falcon1024.v1", Parameters: params, Host: metadata},
	}}
	items, err := resolveHostPlanItems(snapshot, []signerapi.SignRequest{{AuthAddress: "ACCOUNT"}}, []types.Transaction{listTestRekey(listTestTarget)}, nil, nil)
	if err != nil {
		t.Fatalf("listed target: %+v", err)
	}
	if !planHasHostRekey(&PlanResult{HostItems: items}) {
		t.Fatal("a listed rekey is not forced to review")
	}

	rekey := listTestRekey(listTestTarget)
	cfg := policy.DefaultConfig()
	cfg.AutoApproveSelfNoOpTransfer = true
	cfg.Rekeys = policy.RekeysAllow
	plan := &policyeval.PlanFacts{RequestCount: 1, AuthAddressPresent: true}
	if rule, approved := policyeval.ApprovalRule(policyeval.Input{
		Group: []types.Transaction{rekey},
		Slots: []policyeval.Slot{{Index: 0, Policy: cfg, ListedRekeyTargets: items[0].ListedRekeyTargets}},
		Plan:  plan,
	}); approved {
		t.Fatalf("ApprovalRule() approved a listed rekey by %q", rule)
	}
	svc := &Service{PolicyFor: fixedPolicy(cfg)}
	prompted := ""
	outcome, gateErr := svc.runApprovalGates(context.Background(), gateInput{
		AllTxns:            []types.Transaction{rekey},
		EvalCount:          1,
		ListedRekeyTargets: map[int]map[string]bool{0: items[0].ListedRekeyTargets},
		ForcedReviewRuleID: policy.HostRekeyRequiresReviewRuleID,
		Plan:               plan,
		RequestOperatorApproval: func(_ context.Context, rule string) *ServiceError {
			prompted = rule
			return nil
		},
	}, nil)
	if gateErr != nil || outcome.PolicyRuleID != policy.HostRekeyRequiresReviewRuleID || outcome.ApprovalSource != ApprovalSourceHuman || prompted != outcome.PolicyRuleID {
		t.Fatalf("gates = %+v, %v; prompted %q", outcome, gateErr, prompted)
	}
}

// A listed rekey is usually one request, so the single prompt must name the
// handover as the group prompt does, not warn that control is lost.
func TestSingleApprovalNamesAListedHandover(t *testing.T) {
	var got []signerapproval.Violation
	var description string
	svc := &ApprovalService{
		HasClient:      func() bool { return true },
		KnownAddresses: func() map[string]bool { return nil },
		RequestSigningApprovalPrompt: promptFromDecision(func(_, _, _, text string, _, _ uint64, violations []signerapproval.Violation, _ time.Duration) (bool, error) {
			got, description = violations, text
			return true, nil
		}),
	}
	rekey := listTestRekey(listTestTarget)
	item := &hostPlanItem{
		Path: hostPathListedRekey, Metadata: testBoundedMetadata(t, hostmeta.RekeyRefused),
		ListedRekeyTargets: map[string]bool{listTestTarget.String(): true},
	}
	if err := promptSingle(svc, "", signerapi.SignRequest{AuthAddress: "ACCOUNT"}, []types.Transaction{rekey},
		policy.HostRekeyRequiresReviewRuleID, &PlanResult{HostItems: []*hostPlanItem{item}}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0].Message, "rekey-to list") || !strings.Contains(got[0].Message, "LEAVES THIS SIGNER'S CUSTODY") {
		t.Fatalf("single prompt warnings = %+v", got)
	}
	// A lone rekey is the usual case, so its prompt names the authorization too.
	if !strings.Contains(description, "Bounded authorization operation: REKEY") ||
		!strings.Contains(description, "Authorization: spending key only, to an address on the account's rekey-to list") {
		t.Fatalf("single prompt = %q, want the bounded rekey's authorization", description)
	}
	cosigned := &hostPlanItem{Path: hostPathSpendingKeyRekey, Metadata: boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x41}, hostmeta.DefaultCosignerPublicKeySize))}
	if err := promptSingle(svc, "", signerapi.SignRequest{AuthAddress: "ACCOUNT"}, []types.Transaction{rekey},
		policy.HostRekeyRequiresReviewRuleID, &PlanResult{HostItems: []*hostPlanItem{cosigned}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(description, "Authorization: spending key and cosigner") {
		t.Fatalf("single prompt for a cosigned rekey = %q", description)
	}
}
