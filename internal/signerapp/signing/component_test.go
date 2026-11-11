// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	sigverify "github.com/aplane-algo/aplane/internal/sigconstruction/verify"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestPrepareComponentSigningCanonicalizesTargetsAndMessages(t *testing.T) {
	sender := types.Address{1}.String()
	receiver := types.Address{2}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	componentKey := testFalconComponentSelector(t, 0xab)
	req := componentPlanRequest{
		RequestID:     "cli-component-1",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{1, 0},
	}

	plan, err := prepareComponentSigning(req)
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if plan.RequestID != req.RequestID || plan.ComponentKey != componentKey {
		t.Fatalf("plan request metadata = %#v, want request_id %q component_key %q", plan, req.RequestID, componentKey)
	}
	if plan.MessageRole != message.RoleCosigner {
		t.Fatalf("MessageRole = %v, want cosigner", plan.MessageRole)
	}
	if len(plan.Targets) != 2 {
		t.Fatalf("Targets len = %d, want 2", len(plan.Targets))
	}
	for i, target := range plan.Targets {
		if target.TargetIndex != i {
			t.Fatalf("Targets[%d].TargetIndex = %d, want %d", i, target.TargetIndex, i)
		}
		if target.Sender != sender {
			t.Fatalf("Targets[%d].Sender = %q, want %q", i, target.Sender, sender)
		}
		wantMsg := message.ComponentMessage(message.RoleCosigner, plan.Group.Entries[i].TxID)
		if !bytes.Equal(target.Message[:], wantMsg[:]) {
			t.Fatalf("Targets[%d].Message = %x, want %x", i, target.Message, wantMsg)
		}
		if !bytes.Equal(target.TxID[:], algocrypto.TransactionID(txns[i])[:]) {
			t.Fatalf("Targets[%d].TxID = %x, want SDK transaction ID", i, target.TxID)
		}
	}
}

func TestPrepareComponentSigningGeneratesRequestIDWhenMissing(t *testing.T) {
	sender := types.Address{1}.String()
	receiver := types.Address{2}.String()
	txn := paymentTransaction(t, sender, receiver, 7)

	plan, err := prepareComponentSigning(componentPlanRequest{
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if !strings.HasPrefix(plan.RequestID, "cmp-") {
		t.Fatalf("RequestID = %q, want cmp- prefix", plan.RequestID)
	}
}

func TestPrepareComponentSigningUsesCosignerRoleDomain(t *testing.T) {
	sender := types.Address{3}.String()
	receiver := types.Address{4}.String()
	txn := paymentTransaction(t, sender, receiver, 7)

	req := componentPlanRequest{
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}

	plan, err := prepareComponentSigning(req)
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if plan.MessageRole != message.RoleCosigner {
		t.Fatalf("MessageRole = %v, want cosigner", plan.MessageRole)
	}
	// The cosigner signs a domain-tagged message, never the TxID the spending
	// key signs.
	txID := plan.Group.Entries[0].TxID
	if bytes.Equal(plan.Targets[0].Message[:], txID[:]) {
		t.Fatal("cosigner component message is the TxID")
	}
}

func TestPrepareComponentSigningRejectsMalformedGroupBytes(t *testing.T) {
	_, err := prepareComponentSigning(componentPlanRequest{
		Role:          ComponentSignRoleCosigner,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("prepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "invalid msgpack") {
		t.Fatalf("prepareComponentSigning() error = %q, want invalid msgpack", err.Message)
	}
}

func TestPrepareComponentSigningRejectsDivergentGroup(t *testing.T) {
	sender := types.Address{5}.String()
	receiver := types.Address{6}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	txns[1].Group = types.Digest{9}

	_, err := prepareComponentSigning(componentPlanRequest{
		Role:          ComponentSignRoleCosigner,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("prepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "divergent group ID") {
		t.Fatalf("prepareComponentSigning() error = %q, want divergent group ID", err.Message)
	}
}

func TestPrepareComponentSigningRejectsInvalidRequestShape(t *testing.T) {
	// The retired user role is no role at all.
	_, err := prepareComponentSigning(componentPlanRequest{
		Role:          ComponentSignRole("user"),
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("prepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "role must be") {
		t.Fatalf("prepareComponentSigning() error = %q, want unsupported role", err.Message)
	}
}

func TestSigningServiceSignComponentDispatchesAfterValidation(t *testing.T) {
	sender := types.Address{7}.String()
	receiver := types.Address{8}.String()
	txn := paymentTransaction(t, sender, receiver, 10)

	_, err := (&Service{HoldsCosignerKey: holdsAllCosignerKeys}).signComponentWithContext(context.Background(), componentPlanRequest{
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, nil)
	if err == nil || err.Kind != ErrorInternal {
		t.Fatalf("SignComponentWithContext() error = %#v, want internal (policy not loaded)", err)
	}

	_, err = (&Service{}).signComponentWithContext(context.Background(), componentPlanRequest{
		Role:          ComponentSignRole("user"),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("SignComponentWithContext(invalid) error = %#v, want bad request", err)
	}
}

func TestSignComponentCosignerFailsClosedWithoutLoadedPolicyBeforeKeyLoad(t *testing.T) {
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := testnetPaymentTransaction(t, types.Address{20}.String(), types.Address{21}.String(), 1)
	store := &componentKeyStore{}

	_, err := (&Service{HoldsCosignerKey: holdsAllCosignerKeys}).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-no-policy",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorInternal {
		t.Fatalf("SignComponentWithContext() error = %#v, want internal (policy not loaded)", err)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentCosignerRequiresTransferPolicyBeforeKeyLoad(t *testing.T) {
	// A compiled document always carries a transfer policy; build the
	// degenerate shape directly to exercise the defensive check, which must
	// reject rather than let routing sit out.
	cfg := cosignerPolicyConfigForSigningTest(t, "")
	cfg.TransferPolicy = nil
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := testnetPaymentTransaction(t, types.Address{22}.String(), types.Address{23}.String(), 1)
	store := &componentKeyStore{}

	_, err := cosignerTestService(t, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-no-routing",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want a route miss", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentCosignerRejectsNonTransferBeforeKeyLoad(t *testing.T) {
	source := types.Address{24}
	cfg := wildcardCosignerPolicy(t)
	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender:      source,
			Fee:         types.MicroAlgos(1000),
			FirstValid:  10,
			LastValid:   20,
			GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
	}
	store := &componentKeyStore{}

	_, err := cosignerTestService(t, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-appl",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.TransactionTypeRuleID("appl")) {
		t.Fatalf("SignComponentWithContext() error = %q, want the type gate to reject the application call", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentCosignerRejectsRouteMissBeforeKeyLoad(t *testing.T) {
	source := types.Address{25}.String()
	allowed := types.Address{26}.String()
	blocked := types.Address{27}.String()
	cfg := cosignerRoutePolicy(t, source, allowed)
	txn := testnetPaymentTransaction(t, source, blocked, 1)
	store := &componentKeyStore{}

	_, err := cosignerTestService(t, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-route-miss",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want route miss", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestCosignerComponentPolicyIsSelectedByComponentKey(t *testing.T) {
	source := types.Address{25}.String()
	firstDest := types.Address{26}.String()
	secondDest := types.Address{27}.String()
	firstKey := testFalconComponentSelector(t, 0xab)
	secondKey := testFalconComponentSelector(t, 0xcd)
	svc := &Service{
		PolicyFor: keyedPolicy(map[string]*policy.Config{
			firstKey:  cosignerRoutePolicy(t, source, firstDest),
			secondKey: cosignerRoutePolicy(t, source, secondDest),
		}, nil),
		HoldsCosignerKey: holdsAllCosignerKeys,
	}
	txn := testnetPaymentTransaction(t, source, secondDest, 1)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-cosigner-per-key",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  secondKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if signErr := svc.runCosignerGates(plan); signErr != nil {
		t.Fatalf("runCosignerGates() error = %v", signErr)
	}

	plan.ComponentKey = firstKey
	signErr := svc.runCosignerGates(plan)
	if signErr == nil || !strings.Contains(signErr.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("runCosignerGates(first key) error = %#v, want route miss", signErr)
	}
}

func TestSignComponentCosignerRejectsKeyNotHeldBeforePolicy(t *testing.T) {
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := testnetPaymentTransaction(t, types.Address{20}.String(), types.Address{21}.String(), 1)
	store := &componentKeyStore{}
	svc := &Service{
		PolicyFor:        fixedPolicy(wildcardCosignerPolicy(t)),
		HoldsCosignerKey: func(string) bool { return false },
	}
	_, err := svc.signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-not-held",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorBadRequest || !strings.Contains(err.Message, "not found") {
		t.Fatalf("SignComponentWithContext() error = %#v, want key not found", err)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0", store.calls)
	}
}

func TestSignComponentCosignerRejectsInheritedReviewRouteMissBeforeKeyLoad(t *testing.T) {
	// Decode refuses review on a cosigner node; a hand-built config that
	// reviews a route miss must still be rejected, never waited on.
	cfg := cosignerPolicyConfigForSigningTest(t, "")
	cfg.TransferPolicy.OnNoRoute = policy.TransferOnNoRouteReview
	txn := testnetPaymentTransaction(t, types.Address{33}.String(), types.Address{34}.String(), 1)
	store := &componentKeyStore{}

	_, err := cosignerTestService(t, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-review-route-miss",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want the review route miss rejected", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentCosignerRejectsInheritedReviewAboveBeforeKeyLoad(t *testing.T) {
	source := types.Address{35}.String()
	dest := types.Address{36}.String()
	cfg := routingPolicyConfigForSigningTest(t, fmt.Sprintf(`{
  "transfer_policy": {
    "on_no_route": "reject",
    "routes": [
      {
        "id": "inherited_review_route",
        "networks": ["testnet"],
        "sources": [%q],
        "assets": ["algo"],
        "destinations": [%q],
        "limits": {"testnet": {"algo": {"review_above": "1"}}}
      }
    ]
  }
}`, source, dest))
	txn := testnetPaymentTransaction(t, source, dest, 2)
	store := &componentKeyStore{}

	_, err := cosignerTestService(t, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-review-above",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "transfer_policy:inherited_review_route:review_above") {
		t.Fatalf("SignComponentWithContext() error = %q, want inherited review threshold rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentCosignerRejectsRekeyBeforeKeyLoad(t *testing.T) {
	source := types.Address{28}.String()
	dest := types.Address{29}.String()
	txn := testnetPaymentTransaction(t, source, dest, 1)
	txn.RekeyTo = types.Address{30}
	store := &componentKeyStore{}
	audit := &testAuditLogger{}

	_, err := (&Service{
		PolicyFor:        fixedPolicy(cosignerRoutePolicy(t, source, dest)),
		HoldsCosignerKey: holdsAllCosignerKeys,
		AuditLog:         audit,
	}).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-rekey",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.CosignerRekeyRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want rekey rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
	if len(audit.rejected) != 1 {
		t.Fatalf("rejected audit entries = %#v, want one", audit.rejected)
	}
	if got := audit.rejected[0].policyRule; got != policy.CosignerRekeyRuleID {
		t.Fatalf("audit policyRule = %q, want %q", got, policy.CosignerRekeyRuleID)
	}
}

func TestSignComponentCosignerAllowsExplicitRekeyPolicy(t *testing.T) {
	publicKey, privateKey := testFalconComponentKeypair(t, 0x62)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}

	source := types.Address{68}
	target := types.Address{69}
	cfg := cosignerPolicyConfigForSigningTest(t, fmt.Sprintf(`{
  "transfer_policy": {"routes": []},
  "rekey_policy": {
    "allowed": [
      {"sender": %q, "targets": [%q]}
    ]
  }
}`, source.String(), target.String()))
	txn := testnetPaymentTransaction(t, source.String(), source.String(), 0)
	txn.RekeyTo = target
	keyMaterial := &coresigning.KeyMaterial{
		Type:     witness.Falcon1024V1,
		Category: keys.CategoryWitness,
		Value: &coresigning.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	store := &componentKeyStore{key: keyMaterial}

	result, signErr := cosignerTestServiceFor(componentKey, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-rekey-allow",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if signErr != nil {
		t.Fatalf("SignComponentWithContext() error = %v", signErr)
	}
	if store.calls != 1 {
		t.Fatalf("store calls = %d, want 1 after policy approval", store.calls)
	}
	if result == nil || len(result.Signatures) != 1 {
		t.Fatalf("result = %#v, want one signature", result)
	}
}

func TestSignComponentCosignerRejectsUnlistedRekeyTargetBeforeKeyLoad(t *testing.T) {
	source := types.Address{70}
	allowedTarget := types.Address{71}
	blockedTarget := types.Address{72}
	cfg := cosignerPolicyConfigForSigningTest(t, fmt.Sprintf(`{
  "transfer_policy": {"routes": []},
  "rekey_policy": {
    "allowed": [
      {"sender": %q, "targets": [%q]}
    ]
  }
}`, source.String(), allowedTarget.String()))
	txn := testnetPaymentTransaction(t, source.String(), source.String(), 0)
	txn.RekeyTo = blockedTarget
	store := &componentKeyStore{}

	_, err := cosignerTestServiceFor(testFalconComponentSelector(t, 0xbb), cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-rekey-deny",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xbb),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.CosignerRekeyRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want rekey rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentCosignerPolicyAllowsSigning(t *testing.T) {
	publicKey, privateKey := testFalconComponentKeypair(t, 0x61)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}

	source := types.Address{31}.String()
	dest := types.Address{32}.String()
	txn := testnetPaymentTransaction(t, source, dest, 1)
	keyMaterial := &coresigning.KeyMaterial{
		Type:     witness.Falcon1024V1,
		Category: keys.CategoryWitness,
		Value: &coresigning.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	store := &componentKeyStore{key: keyMaterial}
	audit := &testAuditLogger{}

	result, signErr := (&Service{
		PolicyFor:        fixedPolicy(cosignerRoutePolicy(t, source, dest)),
		HoldsCosignerKey: holdsAllCosignerKeys,
		AuditLog:         audit,
	}).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-policy-pass",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if signErr != nil {
		t.Fatalf("SignComponentWithContext() error = %v", signErr)
	}
	if store.calls != 1 || store.gotAddress != componentKey {
		t.Fatalf("store calls = %d address %q, want one call for %q", store.calls, store.gotAddress, componentKey)
	}
	if result == nil || len(result.Signatures) != 1 {
		t.Fatalf("result = %#v, want one signature", result)
	}
	sigBytes, err := hex.DecodeString(result.Signatures[0].Signature)
	if err != nil {
		t.Fatalf("DecodeString(signature) error = %v", err)
	}
	plan, prepErr := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-cosigner-policy-pass",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if prepErr != nil {
		t.Fatalf("prepareComponentSigning() error = %v", prepErr)
	}
	if err := sigverify.Verify(sigconstruction.Falcon1024(), publicKey, plan.Targets[0].Message[:], sigBytes); err != nil {
		t.Fatal("cosigner signature does not verify over component message")
	}
	if len(audit.approved) != 1 || audit.approved[0].authAddress != componentKey {
		t.Fatalf("approved audit entries = %#v, want one component approval", audit.approved)
	}
	// The record names the ID the component message was built from, the one
	// the cosigner signed.
	signedTxID := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(plan.Targets[0].TxID[:])
	if got := audit.approved[0].record.TxID; got != signedTxID {
		t.Fatalf("approved txid = %s, want the signed target %s", got, signedTxID)
	}
}

func TestSigningServiceAssembleCosignedDispatchesAfterValidation(t *testing.T) {
	_, err := (&Service{}).AssembleWithContext(context.Background(), signerapi.AssemblyRequest{
		RequestID:     "asm-1",
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.AssemblyTarget{{Kind: signerapi.AssemblyTargetKindBoundedCosigner,
			TargetIndex:       0,
			AuthAddress:       "ADDR",
			BaseSignatures:    []string{"aa"},
			AssemblyReceipt:   "cc",
			CosignerSignature: "bb",
		}},
	}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AssembleCosignedWithContext() error = %#v, want bad request", err)
	}
	if !strings.Contains(err.Message, "invalid msgpack") {
		t.Fatalf("AssembleCosignedWithContext() error = %q, want invalid msgpack", err.Message)
	}

	_, err = (&Service{}).AssembleWithContext(context.Background(), signerapi.AssemblyRequest{}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AssembleCosignedWithContext(invalid) error = %#v, want bad request", err)
	}
}

// cosignedAssemblyFixture is a cosigned plain host this signer holds, and the
// signatures that authorize its spend of txn: the spending key's base
// signature and receipt, and the cosigner's component signature.
type cosignedAssemblyFixture struct {
	account           string
	bytecode          []byte
	keyMaterial       *coresigning.KeyMaterial
	baseSignature     []byte
	cosignerSignature []byte
	target            signerapi.AssemblyTarget
}

func newCosignedAssemblyFixture(t *testing.T, fill byte, entry canonical.Txn, targetIndex int) cosignedAssemblyFixture {
	t.Helper()
	spendingPublicKey, spendingPrivateKey := testFalconComponentKeypair(t, fill)
	cosignerPublicKey, cosignerPrivateKey := testFalconComponentKeypair(t, fill+1)
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x12, fill}
	account := logicSigAddressForTest(t, bytecode)
	metadata := boundedCosignerTestMetadata(t, cosignerPublicKey)
	metadata.Contract, metadata.SpendEffects, metadata.MaxFee = boundedmeta.PlainContract, nil, nil
	metadata.Layer3Policy = boundedmeta.Layer3PolicyNone
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	baseSignature, err := signerops.New(nil).Sign(spendingPrivateKey, entry.TxID[:])
	if err != nil {
		t.Fatal(err)
	}
	receiptMessage, err := boundedAssemblyReceiptMessage(account, entry.TxID[:], metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signerops.New(nil).Sign(spendingPrivateKey, receiptMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	cosignerMessage := message.ComponentMessage(message.RoleCosigner, entry.TxID)
	cosignerSignature, err := signerops.New(nil).Sign(cosignerPrivateKey, cosignerMessage[:])
	if err != nil {
		t.Fatal(err)
	}
	return cosignedAssemblyFixture{
		account:  account,
		bytecode: bytecode,
		keyMaterial: &coresigning.KeyMaterial{
			Type: "aplane.falcon1024.v1", Category: keys.CategoryDSALsig,
			BaseKeyType: "aplane.falcon1024.v1", PublicKey: append([]byte(nil), spendingPublicKey...),
			Bytecode: append([]byte(nil), bytecode...), BoundedAuthorization: boundedmeta.Clone(metadata),
			SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
		},
		baseSignature:     baseSignature,
		cosignerSignature: cosignerSignature,
		target: signerapi.AssemblyTarget{
			TargetIndex: targetIndex, Kind: signerapi.AssemblyTargetKindBoundedCosigner, AuthAddress: account,
			BaseSignatures:  []string{hex.EncodeToString(baseSignature)},
			AssemblyReceipt: hex.EncodeToString(receipt), CosignerSignature: hex.EncodeToString(cosignerSignature),
		},
	}
}

// Assembly builds a cosigned target from its stored program and both
// signatures, binds it to the account that authorizes it (here an account
// rekeyed to the cosigned one), and preserves a matching passthrough unchanged.
func TestAssembleDecodedCosignedVerifiesAndBuildsSignedGroup(t *testing.T) {
	sender := types.Address{18}.String()
	receiver := types.Address{19}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}
	fixture := newCosignedAssemblyFixture(t, 0x52, group.Entries[0], 0)
	passthroughBytes := msgpack.Encode(types.SignedTxn{Txn: txns[1], Sig: types.Signature{0x01}})

	// Address-keyed: the cosigned target resolves to its key, while the
	// passthrough sender is not held by this signer, so the passthrough is not
	// mistaken for a locally held cosigned account.
	session := &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{fixture.account: fixture.keyMaterial}}
	req := signerapi.AssemblyRequest{
		RequestID:     "asm-live",
		GroupBytesHex: groupBytesHex,
		Targets:       []signerapi.AssemblyTarget{fixture.target},
		Passthrough: []signerapi.AssemblyPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: hex.EncodeToString(passthroughBytes),
		}},
	}

	result, signErr := assembleDecoded(context.Background(), req, group, session)
	if signErr != nil {
		t.Fatalf("assembleDecoded() error = %v", signErr)
	}
	if result.RequestID != req.RequestID {
		t.Fatalf("RequestID = %q, want %q", result.RequestID, req.RequestID)
	}
	if len(result.SignedGroup) != 2 {
		t.Fatalf("SignedGroup len = %d, want 2", len(result.SignedGroup))
	}
	if result.SignedGroup[1] != hex.EncodeToString(passthroughBytes) {
		t.Fatalf("passthrough signed txn = %q, want original passthrough", result.SignedGroup[1])
	}

	signedTargetBytes, err := hex.DecodeString(result.SignedGroup[0])
	if err != nil {
		t.Fatalf("DecodeString(signed target) error = %v", err)
	}
	var signedTarget types.SignedTxn
	if err := msgpack.Decode(signedTargetBytes, &signedTarget); err != nil {
		t.Fatalf("Decode(signed target) error = %v", err)
	}
	if gotTxID, wantTxID := algocrypto.TransactionID(signedTarget.Txn), algocrypto.TransactionID(txns[0]); !bytes.Equal(gotTxID, wantTxID) {
		t.Fatalf("signed target txid = %x, want %x", gotTxID, wantTxID)
	}
	if signedTarget.Txn.Sender.String() != sender {
		t.Fatalf("signed target sender = %q, want %q", signedTarget.Txn.Sender.String(), sender)
	}
	if signedTarget.AuthAddr.String() != fixture.account {
		t.Fatalf("signed target auth address = %q, want cosigned account %q", signedTarget.AuthAddr.String(), fixture.account)
	}
	if !bytes.Equal(signedTarget.Lsig.Logic, fixture.bytecode) {
		t.Fatalf("LogicSig bytecode = %x, want %x", signedTarget.Lsig.Logic, fixture.bytecode)
	}
	if len(signedTarget.Lsig.Args) != 2 || !bytes.Equal(signedTarget.Lsig.Args[0], fixture.baseSignature) ||
		!bytes.Equal(signedTarget.Lsig.Args[1], fixture.cosignerSignature) {
		t.Fatalf("LogicSig args = %x, want the base and cosigner signatures", signedTarget.Lsig.Args)
	}
	if fixture.keyMaterial.Type != "" || fixture.keyMaterial.Bytecode != nil || fixture.keyMaterial.PublicKey != nil {
		t.Fatalf("key material was not zeroed after assembly: %#v", fixture.keyMaterial)
	}
}

// A cosigned account this signer holds signs only through component signing and
// assembly. Supplied as an already-signed passthrough, as its sender or as the
// account a sender is rekeyed to, it is refused, so a passthrough can never
// carry a cosigned account's transaction past the cosigner.
func TestAssembleDecodedRejectsALocallyHeldCosignedAccountAsPassthrough(t *testing.T) {
	cosigned := types.Address{31}.String()
	rekeyed := types.Address{32}.String()
	txn := paymentTransaction(t, cosigned, types.Address{33}.String(), 5)
	rekeyedTxn := paymentTransaction(t, rekeyed, types.Address{33}.String(), 6)
	held := func() *componentKeyTestSession {
		return &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{
			cosigned: {Type: "aplane.falcon1024.v1", BoundedAuthorization: &boundedmeta.Metadata{
				Contract: boundedmeta.PlainContract, Cosigner: &boundedmeta.CosignerAuthorization{Contract: boundedmeta.CosignerContractV1},
			}},
		}}
	}
	var cosignedAddress types.Address
	copy(cosignedAddress[:], mustDecodeAddress(t, cosigned))
	for name, signed := range map[string]types.SignedTxn{
		"as the sender":        {Txn: txn, Sig: types.Signature{0x01}},
		"as the auth address":  {Txn: rekeyedTxn, AuthAddr: cosignedAddress, Sig: types.Signature{0x01}},
		"as a LogicSig sender": {Txn: txn, Lsig: types.LogicSig{Logic: []byte{0x06, 0x81, 0x01}}},
	} {
		t.Run(name, func(t *testing.T) {
			groupBytesHex := []string{txnutil.EncodeWithPrefixHex(signed.Txn)}
			group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			result, err := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
				GroupBytesHex: groupBytesHex,
				Passthrough:   []signerapi.AssemblyPassthroughItem{{TargetIndex: 0, SignedTxnHex: hex.EncodeToString(msgpack.Encode(signed))}},
			}, group, held())
			if result != nil || err == nil || err.Kind != ErrorBadRequest || !strings.Contains(err.Message, "requires component assembly") {
				t.Fatalf("assembleDecoded() = %#v, %#v; want the cosigned passthrough refused", result, err)
			}
		})
	}
	// A held account without a cosigner is an ordinary passthrough.
	uncosigned := &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{
		cosigned: {Type: "aplane.falcon1024.v1", BoundedAuthorization: &boundedmeta.Metadata{Contract: boundedmeta.Contract}},
	}}
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	signed := hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{0x01}}))
	if _, err := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Passthrough:   []signerapi.AssemblyPassthroughItem{{TargetIndex: 0, SignedTxnHex: signed}},
	}, group, uncosigned); err != nil {
		t.Fatalf("assembleDecoded(held account without a cosigner) error = %v", err)
	}
}

func mustDecodeAddress(t *testing.T, address string) []byte {
	t.Helper()
	decoded, err := types.DecodeAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	return decoded[:]
}

func TestAssembleDecodedCosignedGeneratesRequestIDWhenMissing(t *testing.T) {
	txn := paymentTransaction(t, types.Address{17}.String(), types.Address{18}.String(), 7)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}
	passthroughBytes := msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{0x01}})

	result, signErr := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Passthrough: []signerapi.AssemblyPassthroughItem{{
			TargetIndex:  0,
			SignedTxnHex: hex.EncodeToString(passthroughBytes),
		}},
	}, group, &componentKeyTestSession{})
	if signErr != nil {
		t.Fatalf("assembleDecoded() error = %v", signErr)
	}
	if !strings.HasPrefix(result.RequestID, "asm-") {
		t.Fatalf("RequestID = %q, want asm- prefix", result.RequestID)
	}
}

func TestAssembleDecodedCosignedRejectsMismatchedPassthrough(t *testing.T) {
	sender := types.Address{21}.String()
	txn := paymentTransaction(t, sender, types.Address{22}.String(), 16)
	wrongTxn := paymentTransaction(t, sender, types.Address{23}.String(), 17)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}
	wrongSignedBytes := msgpack.Encode(types.SignedTxn{Txn: wrongTxn})

	result, signErr := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
		RequestID:     "asm-bad-passthrough",
		GroupBytesHex: groupBytesHex,
		Passthrough: []signerapi.AssemblyPassthroughItem{{
			TargetIndex:  0,
			SignedTxnHex: hex.EncodeToString(wrongSignedBytes),
		}},
	}, group, &componentKeyTestSession{})
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("assembleDecoded() error = %#v, want bad request", signErr)
	}
	if !strings.Contains(signErr.Message, "signed transaction does not match group transaction") {
		t.Fatalf("assembleDecoded() error = %q, want passthrough mismatch", signErr.Message)
	}
}

func TestSignPreparedCosignerComponentsSignsFalconMessages(t *testing.T) {
	falconkeygen.RegisterWitnessKeygen()
	publicKey, privateKey := testFalconComponentKeypair(t, 0x42)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:     witness.Falcon1024V1,
		Category: keys.CategoryWitness,
		Value: &coresigning.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	session := &componentKeyTestSession{key: keyMaterial}
	plan := preparedCosignerComponentPlan(t, componentKey)

	result, signErr := signPreparedCosignerComponents(context.Background(), plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedCosignerComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != componentKey {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, componentKey)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != componentKey {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, componentKey)
	}
	if len(result.Signatures) != len(plan.Targets) {
		t.Fatalf("Signatures len = %d, want %d", len(result.Signatures), len(plan.Targets))
	}
	for i, sig := range result.Signatures {
		if sig.TargetIndex != plan.Targets[i].TargetIndex {
			t.Fatalf("signature %d target index = %d, want %d", i, sig.TargetIndex, plan.Targets[i].TargetIndex)
		}
		if sig.SignatureScheme != witness.Falcon1024V1 {
			t.Fatalf("signature scheme = %q, want %s", sig.SignatureScheme, witness.Falcon1024V1)
		}
		sigBytes, err := hex.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("DecodeString(signature) error = %v", err)
		}
		if err := sigverify.Verify(sigconstruction.Falcon1024(), publicKey, plan.Targets[i].Message[:], sigBytes); err != nil {
			t.Fatalf("signature %d does not verify over prepared component message", i)
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedCosignerComponentsSignsFalcon1024Messages(t *testing.T) {
	falconkeygen.RegisterWitnessKeygen()

	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x43}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	if len(publicKey) != falconfamily.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(publicKey), falconfamily.PublicKeySize)
	}
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:     witness.Falcon1024V1,
		Category: keys.CategoryWitness,
		Value: &coresigning.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	session := &componentKeyTestSession{key: keyMaterial}
	plan := preparedCosignerComponentPlan(t, componentKey)

	result, signErr := signPreparedCosignerComponents(context.Background(), plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedCosignerComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != componentKey {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, componentKey)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != componentKey {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, componentKey)
	}
	if len(result.Signatures) != len(plan.Targets) {
		t.Fatalf("Signatures len = %d, want %d", len(result.Signatures), len(plan.Targets))
	}
	for i, sig := range result.Signatures {
		if sig.TargetIndex != plan.Targets[i].TargetIndex {
			t.Fatalf("signature %d target index = %d, want %d", i, sig.TargetIndex, plan.Targets[i].TargetIndex)
		}
		if sig.SignatureScheme != witness.Falcon1024V1 {
			t.Fatalf("signature scheme = %q, want %s", sig.SignatureScheme, witness.Falcon1024V1)
		}
		sigBytes, err := hex.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("DecodeString(signature) error = %v", err)
		}
		if err := sigverify.Verify(sigconstruction.Falcon1024(), publicKey, plan.Targets[i].Message[:], sigBytes); err != nil {
			t.Fatalf("signature %d does not verify over prepared component message: %v", i, err)
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedCosignerComponentsRejectsUserRoleBeforeKeyLoad(t *testing.T) {
	sender := types.Address{9}.String()
	receiver := types.Address{10}.String()
	txn := paymentTransaction(t, sender, receiver, 11)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-user",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	// 0x01 named the retired user role; a plan carrying it is refused before
	// any key loads.
	plan.MessageRole = message.Role(0x01)
	session := &componentKeyTestSession{}

	result, signErr := signPreparedCosignerComponents(context.Background(), plan, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedCosignerComponents() error = %#v, want bad request", signErr)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0 before role rejection", session.calls)
	}
}

func TestSignPreparedCosignerComponentsRejectsWrongKeyType(t *testing.T) {
	plan := preparedCosignerComponentPlan(t, testFalconComponentSelector(t, 0x11))
	session := &componentKeyTestSession{key: &coresigning.KeyMaterial{Type: "ed25519"}}

	_, err := signPreparedCosignerComponents(context.Background(), plan, session)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedCosignerComponents() error = %#v, want bad request", err)
	}
}

func groupedPaymentTransactions(t *testing.T, sender, receiver string) []types.Transaction {
	t.Helper()
	txns := []types.Transaction{
		testnetPaymentTransaction(t, sender, receiver, 1),
		testnetPaymentTransaction(t, sender, receiver, 2),
	}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txns[0].Group = groupID
	txns[1].Group = groupID
	return txns
}

func paymentTransaction(t *testing.T, sender, receiver string, amount uint64) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(
		sender,
		receiver,
		amount,
		nil,
		"",
		types.SuggestedParams{
			Fee:             types.MicroAlgos(1000),
			GenesisHash:     []byte("0123456789abcdef0123456789abcdef"),
			GenesisID:       "testnet-v1.0",
			FirstRoundValid: 10,
			LastRoundValid:  20,
		},
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	return txn
}

func testnetPaymentTransaction(t *testing.T, sender, receiver string, amount uint64) types.Transaction {
	t.Helper()
	txn := paymentTransaction(t, sender, receiver, amount)
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	return txn
}

func holdsAllCosignerKeys(string) bool { return true }

func cosignerTestService(t *testing.T, cfg *policy.Config) *Service {
	t.Helper()
	return cosignerTestServiceFor(testFalconComponentSelector(t, 0xab), cfg)
}

func cosignerTestServiceFor(componentKey string, cfg *policy.Config) *Service {
	return &Service{PolicyFor: keyedPolicy(map[string]*policy.Config{componentKey: cfg}, nil), HoldsCosignerKey: holdsAllCosignerKeys}
}

func wildcardCosignerPolicy(t *testing.T) *policy.Config {
	t.Helper()
	return cosignerPolicyConfigForSigningTest(t, `{
  "transfer_policy": {
    "routes": [
      {
        "id": "allow_all_dev",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["*"]
      }
    ]
  }
}`)
}

func cosignerRoutePolicy(t *testing.T, source, destination string) *policy.Config {
	t.Helper()
	return cosignerPolicyConfigForSigningTest(t, fmt.Sprintf(`{
  "transfer_policy": {
    "routes": [
      {
        "id": "allow_test_route",
        "networks": ["testnet"],
        "sources": [%q],
        "assets": ["algo"],
        "destinations": [%q]
      }
    ]
  }
}`, source, destination))
}

func logicSigAddressForTest(t *testing.T, bytecode []byte) string {
	t.Helper()
	lsig := algocrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: append([]byte(nil), bytecode...)},
	}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSigAccount.Address() error = %v", err)
	}
	return address.String()
}

func preparedCosignerComponentPlan(t *testing.T, componentKey string) *ComponentSignPlan {
	t.Helper()
	sender := types.Address{11}.String()
	receiver := types.Address{12}.String()
	txn := paymentTransaction(t, sender, receiver, 12)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-cosigner",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	return plan
}

func testFalconComponentSelector(t *testing.T, fill byte) string {
	t.Helper()
	publicKey := bytes.Repeat([]byte{fill}, falconfamily.PublicKeySize)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	return componentKey
}

func testFalconComponentKeypair(t *testing.T, fill byte) ([]byte, []byte) {
	t.Helper()
	falconkeygen.RegisterWitnessKeygen()
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{fill}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return publicKey, privateKey
}

type componentKeyTestSession struct {
	key        *coresigning.KeyMaterial
	keysByAddr map[string]*coresigning.KeyMaterial // optional per-address lookup; when set, addresses not present return not-found
	err        error
	calls      int
	gotAddress string
}

func (s *componentKeyTestSession) GetKeyWithContext(_ context.Context, address string) (*coresigning.KeyMaterial, error) {
	s.calls++
	s.gotAddress = address
	if s.err != nil {
		return nil, s.err
	}
	if s.keysByAddr != nil {
		km, ok := s.keysByAddr[address]
		if !ok {
			return nil, keystore.ErrKeyNotFound
		}
		return km, nil
	}
	return s.key, nil
}

type componentKeyStore struct {
	key        *coresigning.KeyMaterial
	err        error
	calls      int
	gotAddress string
}

func newComponentKeySession(store *componentKeyStore) *keystore.KeySession {
	session := keystore.NewKeySession(store)
	session.InitializeSession()
	return session
}

func (s *componentKeyStore) List(context.Context) ([]keystore.KeyMetadata, error) {
	return nil, nil
}

func (s *componentKeyStore) Get(_ context.Context, address string) (*coresigning.KeyMaterial, error) {
	s.calls++
	s.gotAddress = address
	if s.err != nil {
		return nil, s.err
	}
	return s.key, nil
}

func (s *componentKeyStore) GetMetadata(context.Context, string) (*keystore.KeyMetadata, error) {
	return nil, nil
}

func (s *componentKeyStore) Delete(context.Context, string) error {
	return nil
}

func (s *componentKeyStore) WithKeyring(func([]byte) error) error {
	return nil
}

func (s *componentKeyStore) Type() string {
	return "test"
}

func TestLoadCosignerComponentKeyMapsMissingKey(t *testing.T) {
	session := &componentKeyTestSession{err: keystore.ErrKeyNotFound}
	_, _, err := loadCosignerComponentKey(context.Background(), session, testFalconComponentSelector(t, 0x22))
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("loadCosignerComponentKey() error = %#v, want bad request", err)
	}
}

func TestLoadCosignerComponentKeyRejectsMismatchedPublicPrivateKey(t *testing.T) {
	_, privateKey := testFalconComponentKeypair(t, 0x44)
	wrongPublicKey, _ := testFalconComponentKeypair(t, 0x45)
	componentKey, err := witness.ID(witness.Falcon1024V1, wrongPublicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:     witness.Falcon1024V1,
		Category: keys.CategoryWitness,
		Value: &coresigning.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    append([]byte(nil), wrongPublicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	_, _, loadErr := loadCosignerComponentKey(context.Background(), session, componentKey)
	if loadErr == nil || loadErr.Kind != ErrorInternal {
		t.Fatalf("loadCosignerComponentKey() error = %#v, want internal", loadErr)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after mismatch: %#v", keyMaterial)
	}
}

func TestValidateCosignedPassthroughRequiresSignatureAndCanonical(t *testing.T) {
	sender := types.Address{1}.String()
	receiver := types.Address{2}.String()
	txn := paymentTransaction(t, sender, receiver, 1)

	group, decodeErr := canonical.DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if decodeErr != nil {
		t.Fatalf("DecodeGroupHex() error = %v", decodeErr)
	}
	entry := group.Entries[0]
	// Sender is not a key this signer holds (the normal passthrough case).
	notHeld := &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{}}

	// Unsigned passthrough is rejected even though its TxID matches.
	unsigned := hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
	if _, err := validateCosignedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: unsigned}, entry, notHeld); err == nil {
		t.Fatal("unsigned passthrough: expected rejection, got nil")
	}

	// A signed passthrough whose txn matches the canonical entry is accepted.
	signed := hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{0x01}}))
	if _, err := validateCosignedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: signed}, entry, notHeld); err != nil {
		t.Fatalf("signed passthrough: unexpected error %v", err)
	}

	// A passthrough whose sender is a locally held cosigned account is rejected:
	// it must go through component assembly, not passthrough.
	cosignedSession := &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{
		sender: {Type: "aplane.falcon1024.v1", BoundedAuthorization: &boundedmeta.Metadata{Cosigner: &boundedmeta.CosignerAuthorization{}}},
	}}
	if _, err := validateCosignedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: signed}, entry, cosignedSession); err == nil {
		t.Fatal("cosigned-account passthrough: expected rejection, got nil")
	}

	// A non-not-found keystore error (e.g. locked session, decrypt failure) must
	// fail closed rather than be treated as a foreign passthrough.
	erroringSession := &componentKeyTestSession{err: fmt.Errorf("session locked")}
	if _, err := validateCosignedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: signed}, entry, erroringSession); err == nil {
		t.Fatal("keystore error passthrough: expected fail-closed error, got nil")
	}
}

type limitedCosignerAuditLogger struct {
	testAuditLogger
	limited []testAuditEntry
}

func (l *limitedCosignerAuditLogger) LogCosignerComponentRejected(witnessKeyID, txnSender, reason, policyRuleID string) {
	l.limited = append(l.limited, testAuditEntry{authAddress: witnessKeyID, txnSender: txnSender, reason: reason, policyRule: policyRuleID})
}

// Cosigner policy rejections go through the rate-limited audit path when the
// audit log offers one, so a caller provoking rejections cannot rotate the
// cosigner's signing record out of the log.
func TestCosignerPolicyRejectionUsesLimitedAuditPath(t *testing.T) {
	source := types.Address{28}.String()
	dest := types.Address{29}.String()
	txn := testnetPaymentTransaction(t, source, dest, 1)
	txn.RekeyTo = types.Address{30}
	audit := &limitedCosignerAuditLogger{}

	_, err := (&Service{
		PolicyFor:        fixedPolicy(cosignerRoutePolicy(t, source, dest)),
		HoldsCosignerKey: holdsAllCosignerKeys,
		AuditLog:         audit,
	}).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-limited-audit",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(&componentKeyStore{}))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if len(audit.rejected) != 0 {
		t.Fatalf("unlimited rejection entries = %#v, want none", audit.rejected)
	}
	if len(audit.limited) != 1 || audit.limited[0].policyRule != policy.CosignerRekeyRuleID || audit.limited[0].txnSender != source {
		t.Fatalf("limited rejection entries = %#v, want one rekey rejection for %s", audit.limited, source)
	}
}

// embeddedCosignerDefaultConfig compiles the shipped cosigner default: every
// type rejected, no routes, rekeys rejected.
func embeddedCosignerDefaultConfig(t *testing.T) *policy.Config {
	t.Helper()
	data, err := policy.EmbeddedDefault(noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policy.DecodePolicyV1(data, policy.DefaultKey, noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decoded.Compile(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// A cosigner key with no document of its own follows the deny-all default:
// a payment and an application call are both rejected by the type gate,
// which runs before routing, and the key is never loaded.
func TestSignComponentCosignerKeyOnDenyAllDefaultRejectsEverything(t *testing.T) {
	source := types.Address{90}
	svc := &Service{PolicyFor: keyedPolicy(nil, embeddedCosignerDefaultConfig(t)), HoldsCosignerKey: holdsAllCosignerKeys}
	header := types.Header{
		Sender:      source,
		Fee:         types.MicroAlgos(1000),
		FirstValid:  10,
		LastValid:   20,
		GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
	}
	for name, txn := range map[string]types.Transaction{
		"pay":  {Type: types.PaymentTx, Header: header, PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{91}, Amount: 1}},
		"appl": {Type: types.ApplicationCallTx, Header: header, ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{ApplicationID: 5}}},
	} {
		store := &componentKeyStore{}
		_, err := svc.signComponentWithContext(context.Background(), componentPlanRequest{
			RequestID:     "cmp-cosigner-default-" + name,
			Role:          ComponentSignRoleCosigner,
			ComponentKey:  testFalconComponentSelector(t, 0xab),
			GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
			TargetIndices: []int{0},
		}, newComponentKeySession(store))
		if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, policy.TransactionTypeRuleID(name)) {
			t.Fatalf("%s: error = %#v, want %s rejected by the default", name, err, policy.TransactionTypeRuleID(name))
		}
		if store.calls != 0 {
			t.Fatalf("%s: store calls = %d, want 0 before policy rejection", name, store.calls)
		}
	}

	// A document of its own that allows pay but routes nothing rejects the
	// same payment as a route miss instead.
	own := cosignerPolicyConfigForSigningTest(t, "")
	svc = &Service{PolicyFor: keyedPolicy(map[string]*policy.Config{testFalconComponentSelector(t, 0xab): own}, embeddedCosignerDefaultConfig(t)), HoldsCosignerKey: holdsAllCosignerKeys}
	pay := types.Transaction{Type: types.PaymentTx, Header: header, PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{91}, Amount: 1}}
	_, err := svc.signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-own-route-miss",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(pay)},
		TargetIndices: []int{0},
	}, newComponentKeySession(&componentKeyStore{}))
	if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("own document without routes: error = %#v, want a route miss", err)
	}
}

// A rekey that rekey_policy allows is still refused when its genesis hash names
// no network this node recognizes: the cosigner fails closed on an unknown
// network before any rekey or routing rule runs, and never loads the key.
func TestSignComponentCosignerRejectsAllowedRekeyOnUnknownNetwork(t *testing.T) {
	publicKey, _ := testFalconComponentKeypair(t, 0x63)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	source := types.Address{78}
	target := types.Address{79}
	cfg := cosignerPolicyConfigForSigningTest(t, fmt.Sprintf(`{
  "transfer_policy": {"routes": []},
  "rekey_policy": {
    "allowed": [
      {"sender": %q, "targets": [%q]}
    ]
  }
}`, source.String(), target.String()))
	txn := testnetPaymentTransaction(t, source.String(), source.String(), 0)
	txn.RekeyTo = target
	txn.GenesisHash = types.Digest{0xde, 0xad, 0xbe, 0xef}
	store := &componentKeyStore{}

	_, signErr := cosignerTestServiceFor(componentKey, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-rekey-unknown-network",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if signErr == nil || signErr.Kind != ErrorForbidden || !strings.Contains(signErr.Message, policy.UnknownGenesisHashRuleID) {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden %s", signErr, policy.UnknownGenesisHashRuleID)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}
