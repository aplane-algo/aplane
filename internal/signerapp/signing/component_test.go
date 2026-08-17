// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falcon1024guarded "github.com/aplane-algo/aplane/lsig/falcon1024_guarded"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func init() {
	falcon1024guarded.RegisterClient()
}

var (
	_ ComponentPacker = (*falcon1024guarded.Provider)(nil)
)

func TestPrepareComponentSigningCanonicalizesTargetsAndMessages(t *testing.T) {
	sender := types.Address{1}.String()
	receiver := types.Address{2}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	req := componentPlanRequest{
		RequestID:     "cli-component-1",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{1, 0},
	}

	plan, err := prepareComponentSigning(req)
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if plan.RequestID != req.RequestID || plan.ComponentKey != sender {
		t.Fatalf("plan request metadata = %#v, want request_id %q component_key %q", plan, req.RequestID, sender)
	}
	if plan.MessageRole != message.RoleUser {
		t.Fatalf("MessageRole = %v, want user", plan.MessageRole)
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
		wantMsg := message.ComponentMessage(message.RoleUser, plan.Group.Entries[i].TxID)
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
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
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

func TestPrepareComponentSigningUsesSentryRoleDomain(t *testing.T) {
	sender := types.Address{3}.String()
	receiver := types.Address{4}.String()
	txn := paymentTransaction(t, sender, receiver, 7)

	req := componentPlanRequest{
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}

	plan, err := prepareComponentSigning(req)
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if plan.MessageRole != message.RoleSentry {
		t.Fatalf("MessageRole = %v, want sentry", plan.MessageRole)
	}
	userMsg := message.ComponentMessage(message.RoleUser, plan.Group.Entries[0].TxID)
	if bytes.Equal(plan.Targets[0].Message[:], userMsg[:]) {
		t.Fatal("sentry component message matched user-role message")
	}
}

func TestPrepareComponentSigningRejectsMalformedGroupBytes(t *testing.T) {
	_, err := prepareComponentSigning(componentPlanRequest{
		Role:          signerapi.ComponentSignRoleSentry,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("prepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "decode transaction") {
		t.Fatalf("prepareComponentSigning() error = %q, want decode transaction", err.Message)
	}
}

func TestPrepareComponentSigningRejectsDivergentGroup(t *testing.T) {
	sender := types.Address{5}.String()
	receiver := types.Address{6}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	txns[1].Group = types.Digest{9}

	_, err := prepareComponentSigning(componentPlanRequest{
		Role:          signerapi.ComponentSignRoleSentry,
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
	_, err := prepareComponentSigning(componentPlanRequest{
		Role:          signerapi.ComponentSignRoleUser,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("prepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "component_key is required") {
		t.Fatalf("prepareComponentSigning() error = %q, want missing component_key", err.Message)
	}
}

func TestSigningServiceSignComponentDispatchesAfterValidation(t *testing.T) {
	sender := types.Address{7}.String()
	receiver := types.Address{8}.String()
	txn := paymentTransaction(t, sender, receiver, 10)

	_, err := (&Service{}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, nil)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryPolicyMissingRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want missing sentry policy", err.Message)
	}

	_, err = (&Service{}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		Role:          signerapi.ComponentSignRoleUser,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("SignComponentWithContext(invalid) error = %#v, want bad request", err)
	}
}

func TestSignComponentSentryRequiresPolicyBeforeKeyLoad(t *testing.T) {
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := testnetPaymentTransaction(t, types.Address{20}.String(), types.Address{21}.String(), 1)
	store := &componentKeyStore{}

	_, err := (&Service{}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-no-policy",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryPolicyMissingRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want missing sentry policy", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentSentryRequiresTransferPolicyBeforeKeyLoad(t *testing.T) {
	cfg := sentryPolicyConfigForSigningTest(t, `{}`)
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := testnetPaymentTransaction(t, types.Address{22}.String(), types.Address{23}.String(), 1)
	store := &componentKeyStore{}

	_, err := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-no-routing",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryTransferPolicyRequiredRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want transfer policy required", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentSentryRejectsNonTransferBeforeKeyLoad(t *testing.T) {
	source := types.Address{24}
	cfg := wildcardSentryPolicy(t)
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

	_, err := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-appl",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryNonTransferRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want non-transfer rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentSentryRejectsRouteMissBeforeKeyLoad(t *testing.T) {
	source := types.Address{25}.String()
	allowed := types.Address{26}.String()
	blocked := types.Address{27}.String()
	cfg := sentryRoutePolicy(t, source, allowed)
	txn := testnetPaymentTransaction(t, source, blocked, 1)
	store := &componentKeyStore{}

	_, err := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-route-miss",
		Role:          signerapi.ComponentSignRoleSentry,
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

func TestSentryComponentPolicyUsesComponentKeyOverride(t *testing.T) {
	source := types.Address{25}.String()
	baseDest := types.Address{26}.String()
	overrideDest := types.Address{27}.String()
	componentKey := testFalconComponentSelector(t, 0xab)
	otherComponentKey := testFalconComponentSelector(t, 0xcd)
	cfg := sentryPolicyConfigForSigningTest(t, fmt.Sprintf(`
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: base_route
      networks: [testnet]
      sources: [%q]
      assets: ["algo"]
      destinations: [%q]
key_overrides:
  %s:
    transfer_policy:
      schema_version: 1
      enabled: true
      routes:
        - id: override_route
          networks: [testnet]
          sources: [%q]
          assets: ["algo"]
          destinations: [%q]
`, source, baseDest, componentKey, source, overrideDest))
	txn := testnetPaymentTransaction(t, source, overrideDest, 1)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-sentry-key-override",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if signErr := (&Service{SentryPolicy: cfg}).evaluateSentryComponentPolicy("default", plan); signErr != nil {
		t.Fatalf("evaluateSentryComponentPolicy() error = %v", signErr)
	}

	plan.ComponentKey = otherComponentKey
	signErr := (&Service{SentryPolicy: cfg}).evaluateSentryComponentPolicy("default", plan)
	if signErr == nil || !strings.Contains(signErr.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("evaluateSentryComponentPolicy(other key) error = %#v, want route miss", signErr)
	}
}

func TestSignComponentSentryRejectsInheritedReviewRouteMissBeforeKeyLoad(t *testing.T) {
	cfg := sentryPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  routes: []
`)
	cfg.TransferPolicy.OnNoRoute = policy.TransferOnNoRouteReview
	txn := testnetPaymentTransaction(t, types.Address{33}.String(), types.Address{34}.String(), 1)
	store := &componentKeyStore{}

	_, err := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-review-route-miss",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryDeterministicRoutingRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want deterministic routing rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentSentryRejectsInheritedReviewAboveBeforeKeyLoad(t *testing.T) {
	source := types.Address{35}.String()
	dest := types.Address{36}.String()
	cfg := routingPolicyConfigForSigningTest(t, fmt.Sprintf(`
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: inherited_review_route
      networks: [testnet]
      sources: [%q]
      assets: ["algo"]
      destinations: [%q]
      limits:
        review_above: 1
`, source, dest))
	txn := testnetPaymentTransaction(t, source, dest, 2)
	store := &componentKeyStore{}

	_, err := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-review-above",
		Role:          signerapi.ComponentSignRoleSentry,
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

func TestSignComponentSentryRejectsRekeyBeforeKeyLoad(t *testing.T) {
	source := types.Address{28}.String()
	dest := types.Address{29}.String()
	txn := testnetPaymentTransaction(t, source, dest, 1)
	txn.RekeyTo = types.Address{30}
	store := &componentKeyStore{}
	audit := &testAuditLogger{}

	_, err := (&Service{
		SentryPolicy: sentryRoutePolicy(t, source, dest),
		AuditLog:     audit,
	}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-rekey",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  testFalconComponentSelector(t, 0xab),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryRekeyRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want rekey rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
	if len(audit.rejected) != 1 {
		t.Fatalf("rejected audit entries = %#v, want one", audit.rejected)
	}
	if got := audit.rejected[0].policyRule; got != policy.SentryRekeyRuleID {
		t.Fatalf("audit policyRule = %q, want %q", got, policy.SentryRekeyRuleID)
	}
}

func TestSignComponentSentryAllowsExplicitRekeyPolicy(t *testing.T) {
	publicKey, privateKey := testFalconComponentKeypair(t, 0x62)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}

	source := types.Address{68}
	target := types.Address{69}
	cfg := sentryPolicyConfigForSigningTest(t, fmt.Sprintf(`
transfer_policy:
  schema_version: 1
  enabled: true
  routes: []
rekey_policy:
  allowed:
    - sender: %q
      targets: [%q]
`, source.String(), target.String()))
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

	result, signErr := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-rekey-allow",
		Role:          signerapi.ComponentSignRoleSentry,
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

func TestSignComponentSentryRejectsUnlistedRekeyTargetBeforeKeyLoad(t *testing.T) {
	source := types.Address{70}
	allowedTarget := types.Address{71}
	blockedTarget := types.Address{72}
	cfg := sentryPolicyConfigForSigningTest(t, fmt.Sprintf(`
transfer_policy:
  schema_version: 1
  enabled: true
  routes: []
rekey_policy:
  allowed:
    - sender: %q
      targets: [%q]
`, source.String(), allowedTarget.String()))
	txn := testnetPaymentTransaction(t, source.String(), source.String(), 0)
	txn.RekeyTo = blockedTarget
	store := &componentKeyStore{}

	_, err := (&Service{SentryPolicy: cfg}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-rekey-deny",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  testFalconComponentSelector(t, 0xbb),
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponentWithContext() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, policy.SentryRekeyRuleID) {
		t.Fatalf("SignComponentWithContext() error = %q, want rekey rejection", err.Message)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0 before policy rejection", store.calls)
	}
}

func TestSignComponentSentryPolicyAllowsSigning(t *testing.T) {
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
		SentryPolicy: sentryRoutePolicy(t, source, dest),
		AuditLog:     audit,
	}).signComponentWithContext(context.Background(), "default", componentPlanRequest{
		RequestID:     "cmp-sentry-policy-pass",
		Role:          signerapi.ComponentSignRoleSentry,
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
		RequestID:     "cmp-sentry-policy-pass",
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if prepErr != nil {
		t.Fatalf("prepareComponentSigning() error = %v", prepErr)
	}
	if err := verify.VerifyFalcon1024(publicKey, plan.Targets[0].Message[:], sigBytes); err != nil {
		t.Fatal("sentry signature does not verify over component message")
	}
	if len(audit.approved) != 1 || audit.approved[0].authAddress != componentKey {
		t.Fatalf("approved audit entries = %#v, want one component approval", audit.approved)
	}
}

func TestSignPreparedUserComponentsSignsGuardedAccountMessages(t *testing.T) {
	baseKeyType := "test.user-component-signing.v1"
	provider := &componentUserTestProvider{family: baseKeyType}
	coresigning.Register(provider)

	sender := types.Address{13}.String()
	receiver := types.Address{14}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-user",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{0, 1},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:        keytypes.GuardedFalcon1024Sentry1024V1,
		Category:    keys.CategoryDSALsig,
		BaseKeyType: baseKeyType,
		Bytecode:    []byte{0x01, 0x02, 0x03},
		Value:       []byte{0xaa, 0xbb, 0xcc},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := signPreparedUserComponents(context.Background(), plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedUserComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != sender {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, sender)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != sender {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, sender)
	}
	if len(result.Signatures) != len(plan.Targets) {
		t.Fatalf("Signatures len = %d, want %d", len(result.Signatures), len(plan.Targets))
	}
	if len(provider.messages) != len(plan.Targets) {
		t.Fatalf("provider messages len = %d, want %d", len(provider.messages), len(plan.Targets))
	}
	for i, sig := range result.Signatures {
		if sig.TargetIndex != plan.Targets[i].TargetIndex {
			t.Fatalf("signature %d target index = %d, want %d", i, sig.TargetIndex, plan.Targets[i].TargetIndex)
		}
		if sig.SignatureScheme != baseKeyType {
			t.Fatalf("signature scheme = %q, want %s", sig.SignatureScheme, baseKeyType)
		}
		if !bytes.Equal(provider.messages[i], plan.Targets[i].Message[:]) {
			t.Fatalf("provider message %d = %x, want %x", i, provider.messages[i], plan.Targets[i].Message)
		}
		gotSignature, err := hex.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("DecodeString(signature) error = %v", err)
		}
		if !bytes.Equal(gotSignature, provider.signatures[i]) {
			t.Fatalf("signature %d = %x, want provider signature %x", i, gotSignature, provider.signatures[i])
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil || keyMaterial.Bytecode != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedUserComponentsSignsGuardedAuthorizerMessages(t *testing.T) {
	baseKeyType := "test.user-component-authorizer-signing.v1"
	provider := &componentUserTestProvider{family: baseKeyType}
	coresigning.Register(provider)

	sender := types.Address{15}.String()
	receiver := types.Address{16}.String()
	componentKey := types.Address{17}.String()
	txn := paymentTransaction(t, sender, receiver, 13)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-user-mismatch",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	if plan.Targets[0].Sender != sender {
		t.Fatalf("prepared target sender = %q, want %q", plan.Targets[0].Sender, sender)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:        keytypes.GuardedFalcon1024Sentry1024V1,
		Category:    keys.CategoryDSALsig,
		BaseKeyType: baseKeyType,
		Bytecode:    []byte{0x01, 0x02, 0x04},
		Value:       []byte{0xdd, 0xee, 0xff},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := signPreparedUserComponents(context.Background(), plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedUserComponents() error = %v", signErr)
	}
	if session.calls != 1 || session.gotAddress != componentKey {
		t.Fatalf("session calls = %d address %q, want one call for %q", session.calls, session.gotAddress, componentKey)
	}
	if result.RequestID != plan.RequestID || result.ComponentKey != componentKey {
		t.Fatalf("result metadata = %#v, want request_id %q component_key %q", result, plan.RequestID, componentKey)
	}
	if len(result.Signatures) != 1 || len(provider.messages) != 1 {
		t.Fatalf("signatures = %d provider messages = %d, want one each", len(result.Signatures), len(provider.messages))
	}
	if result.Signatures[0].TargetIndex != 0 {
		t.Fatalf("signature target index = %d, want 0", result.Signatures[0].TargetIndex)
	}
	if result.Signatures[0].SignatureScheme != baseKeyType {
		t.Fatalf("signature scheme = %q, want %s", result.Signatures[0].SignatureScheme, baseKeyType)
	}
	if !bytes.Equal(provider.messages[0], plan.Targets[0].Message[:]) {
		t.Fatalf("provider message = %x, want %x", provider.messages[0], plan.Targets[0].Message)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil || keyMaterial.Bytecode != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSigningServiceAssembleGuardedDispatchesAfterValidation(t *testing.T) {
	_, err := (&Service{}).AssembleWithContext(context.Background(), "default", signerapi.AssemblyRequest{
		RequestID:     "asm-1",
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.AssemblyTarget{{Kind: signerapi.AssemblyTargetKindGuarded,
			TargetIndex:     0,
			AuthAddress:     "ADDR",
			UserSignature:   "aa",
			SentrySignature: "bb",
		}},
	}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AssembleGuardedWithContext() error = %#v, want bad request", err)
	}
	if !strings.Contains(err.Message, "decode transaction") {
		t.Fatalf("AssembleGuardedWithContext() error = %q, want decode transaction", err.Message)
	}

	_, err = (&Service{}).AssembleWithContext(context.Background(), "default", signerapi.AssemblyRequest{}, nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AssembleGuardedWithContext(invalid) error = %#v, want bad request", err)
	}
}

func TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup(t *testing.T) {
	sentryPublicKey, sentryPrivateKey := testFalconComponentKeypair(t, 0x52)

	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x53}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x12, 0x34}
	guardedAccount := logicSigAddressForTest(t, bytecode)
	sender := types.Address{18}.String()
	receiver := types.Address{19}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}

	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	userSignature, err := signerops.New(nil).Sign(userPrivateKey, userMsg[:])
	if err != nil {
		t.Fatalf("Sign(user) error = %v", err)
	}
	sentryMsg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	sentrySignature, err := signerops.New(nil).Sign(sentryPrivateKey, sentryMsg[:])
	if err != nil {
		t.Fatalf("Sign(sentry) error = %v", err)
	}
	passthroughBytes := msgpack.Encode(types.SignedTxn{Txn: txns[1], Sig: types.Signature{0x01}})

	keyMaterial := &coresigning.KeyMaterial{
		Type:                   keytypes.GuardedFalcon1024Sentry1024V1,
		Category:               keys.CategoryDSALsig,
		BaseKeyType:            falcon1024guarded.BaseKeyType,
		PublicKey:              append([]byte(nil), userPublicKey...),
		Bytecode:               append([]byte(nil), bytecode...),
		Parameters:             map[string]string{keytypes.ParameterSentryPublicKey: hex.EncodeToString(sentryPublicKey)},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), userPrivateKey...)},
	}
	// Address-keyed: the guarded target resolves to its key, while the
	// passthrough sender is not held by this signer (so the passthrough is not
	// mistaken for a locally-held guarded account).
	session := &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{guardedAccount: keyMaterial}}
	req := signerapi.AssemblyRequest{
		RequestID:     "asm-live",
		GroupBytesHex: groupBytesHex,
		Targets: []signerapi.AssemblyTarget{{Kind: signerapi.AssemblyTargetKindGuarded,
			TargetIndex:     0,
			AuthAddress:     guardedAccount,
			UserSignature:   hex.EncodeToString(userSignature),
			SentrySignature: hex.EncodeToString(sentrySignature),
		}},
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
	gotTxID := algocrypto.TransactionID(signedTarget.Txn)
	wantTxID := algocrypto.TransactionID(txns[0])
	if !bytes.Equal(gotTxID, wantTxID) {
		t.Fatalf("signed target txid = %x, want %x", gotTxID, wantTxID)
	}
	if signedTarget.Txn.Sender.String() != sender {
		t.Fatalf("signed target sender = %q, want %q", signedTarget.Txn.Sender.String(), sender)
	}
	if signedTarget.AuthAddr.String() != guardedAccount {
		t.Fatalf("signed target auth address = %q, want guarded account %q", signedTarget.AuthAddr.String(), guardedAccount)
	}
	if !bytes.Equal(signedTarget.Lsig.Logic, bytecode) {
		t.Fatalf("LogicSig bytecode = %x, want %x", signedTarget.Lsig.Logic, bytecode)
	}
	if len(signedTarget.Lsig.Args) != 2 {
		t.Fatalf("LogicSig args len = %d, want 2", len(signedTarget.Lsig.Args))
	}
	if !bytes.Equal(signedTarget.Lsig.Args[0], userSignature) {
		t.Fatalf("LogicSig arg 0 = %x, want user signature %x", signedTarget.Lsig.Args[0], userSignature)
	}
	if !bytes.Equal(signedTarget.Lsig.Args[1], sentrySignature) {
		t.Fatalf("LogicSig arg 1 = %x, want sentry signature %x", signedTarget.Lsig.Args[1], sentrySignature)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil || keyMaterial.Bytecode != nil || keyMaterial.PublicKey != nil {
		t.Fatalf("key material was not zeroed after assembly: %#v", keyMaterial)
	}
}

func TestAssembleDecodedGuardedGeneratesRequestIDWhenMissing(t *testing.T) {
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

func TestAssembleDecodedGuardedVerifiesFalconSentryAndBuildsSignedGroup(t *testing.T) {
	sentryPublicKey, sentryPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x54}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair(sentry) error = %v", err)
	}
	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x55}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair(user) error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0xab, 0xcd}
	guardedAccount := logicSigAddressForTest(t, bytecode)
	txn := paymentTransaction(t, guardedAccount, types.Address{19}.String(), 14)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}

	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	userSignature, err := signerops.New(nil).Sign(userPrivateKey, userMsg[:])
	if err != nil {
		t.Fatalf("Sign(user) error = %v", err)
	}
	sentryMsg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	sentrySignature, err := signerops.New(nil).Sign(sentryPrivateKey, sentryMsg[:])
	if err != nil {
		t.Fatalf("Sign(sentry) error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:                   keytypes.GuardedFalcon1024Sentry1024V1,
		Category:               keys.CategoryDSALsig,
		BaseKeyType:            falcon1024guarded.BaseKeyType,
		PublicKey:              append([]byte(nil), userPublicKey...),
		Bytecode:               append([]byte(nil), bytecode...),
		Parameters:             map[string]string{keytypes.ParameterSentryPublicKey: hex.EncodeToString(sentryPublicKey)},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), userPrivateKey...)},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
		RequestID:     "asm-falcon-sentry",
		GroupBytesHex: groupBytesHex,
		Targets: []signerapi.AssemblyTarget{{Kind: signerapi.AssemblyTargetKindGuarded,
			TargetIndex:     0,
			AuthAddress:     guardedAccount,
			UserSignature:   hex.EncodeToString(userSignature),
			SentrySignature: hex.EncodeToString(sentrySignature),
		}},
	}, group, session)
	if signErr != nil {
		t.Fatalf("assembleDecoded() error = %v", signErr)
	}
	if len(result.SignedGroup) != 1 {
		t.Fatalf("SignedGroup len = %d, want 1", len(result.SignedGroup))
	}
	signedTargetBytes, err := hex.DecodeString(result.SignedGroup[0])
	if err != nil {
		t.Fatalf("DecodeString(signed target) error = %v", err)
	}
	var signedTarget types.SignedTxn
	if err := msgpack.Decode(signedTargetBytes, &signedTarget); err != nil {
		t.Fatalf("Decode(signed target) error = %v", err)
	}
	if len(signedTarget.Lsig.Args) != 2 {
		t.Fatalf("LogicSig args len = %d, want 2", len(signedTarget.Lsig.Args))
	}
	if !bytes.Equal(signedTarget.Lsig.Args[0], userSignature) {
		t.Fatalf("LogicSig arg 0 = %x, want user signature %x", signedTarget.Lsig.Args[0], userSignature)
	}
	if !bytes.Equal(signedTarget.Lsig.Args[1], sentrySignature) {
		t.Fatalf("LogicSig arg 1 = %x, want sentry signature %x", signedTarget.Lsig.Args[1], sentrySignature)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil || keyMaterial.Bytecode != nil || keyMaterial.PublicKey != nil {
		t.Fatalf("key material was not zeroed after assembly: %#v", keyMaterial)
	}
}

func TestAssembleDecodedGuardedRejectsWrongSentrySignature(t *testing.T) {
	sentryPublicKey, _ := testFalconComponentKeypair(t, 0x54)
	_, wrongPrivateKey := testFalconComponentKeypair(t, 0x55)

	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x56}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x56, 0x78}
	guardedAccount := logicSigAddressForTest(t, bytecode)
	txn := paymentTransaction(t, guardedAccount, types.Address{19}.String(), 14)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}

	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	userSignature, err := signerops.New(nil).Sign(userPrivateKey, userMsg[:])
	if err != nil {
		t.Fatalf("Sign(user) error = %v", err)
	}
	sentryMsg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	wrongSignature, err := signerops.New(nil).Sign(wrongPrivateKey, sentryMsg[:])
	if err != nil {
		t.Fatalf("Sign(wrong sentry) error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:                   keytypes.GuardedFalcon1024Sentry1024V1,
		Category:               keys.CategoryDSALsig,
		BaseKeyType:            falcon1024guarded.BaseKeyType,
		PublicKey:              append([]byte(nil), userPublicKey...),
		Bytecode:               append([]byte(nil), bytecode...),
		Parameters:             map[string]string{keytypes.ParameterSentryPublicKey: hex.EncodeToString(sentryPublicKey)},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), userPrivateKey...)},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
		RequestID:     "asm-bad-sentry",
		GroupBytesHex: groupBytesHex,
		Targets: []signerapi.AssemblyTarget{{Kind: signerapi.AssemblyTargetKindGuarded,
			TargetIndex:     0,
			AuthAddress:     guardedAccount,
			UserSignature:   hex.EncodeToString(userSignature),
			SentrySignature: hex.EncodeToString(wrongSignature),
		}},
	}, group, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("assembleDecoded() error = %#v, want bad request", signErr)
	}
	if !strings.Contains(signErr.Message, "sentry_signature invalid") {
		t.Fatalf("assembleDecoded() error = %q, want sentry_signature invalid", signErr.Message)
	}
}

func TestAssembleDecodedGuardedRejectsWrongUserSignature(t *testing.T) {
	sentryPublicKey, sentryPrivateKey := testFalconComponentKeypair(t, 0x57)

	userPublicKey, userPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x58}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair(user) error = %v", err)
	}
	_, wrongUserPrivateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x59}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair(wrong user) error = %v", err)
	}
	bytecode := []byte{0x06, 0x20, 0x01, 0x01, 0x22, 0x9a, 0xbc}
	guardedAccount := logicSigAddressForTest(t, bytecode)
	txn := paymentTransaction(t, guardedAccount, types.Address{20}.String(), 15)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", decodeErr)
	}

	userMsg := message.ComponentMessage(message.RoleUser, group.Entries[0].TxID)
	wrongUserSignature, err := signerops.New(nil).Sign(wrongUserPrivateKey, userMsg[:])
	if err != nil {
		t.Fatalf("Sign(wrong user) error = %v", err)
	}
	sentryMsg := message.ComponentMessage(message.RoleSentry, group.Entries[0].TxID)
	sentrySignature, err := signerops.New(nil).Sign(sentryPrivateKey, sentryMsg[:])
	if err != nil {
		t.Fatalf("Sign(sentry) error = %v", err)
	}

	keyMaterial := &coresigning.KeyMaterial{
		Type:                   keytypes.GuardedFalcon1024Sentry1024V1,
		Category:               keys.CategoryDSALsig,
		BaseKeyType:            falcon1024guarded.BaseKeyType,
		PublicKey:              append([]byte(nil), userPublicKey...),
		Bytecode:               append([]byte(nil), bytecode...),
		Parameters:             map[string]string{keytypes.ParameterSentryPublicKey: hex.EncodeToString(sentryPublicKey)},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		Value:                  &coresigning.LsigKeyMaterial{PrivateKey: append([]byte(nil), userPrivateKey...)},
	}
	session := &componentKeyTestSession{key: keyMaterial}

	result, signErr := assembleDecoded(context.Background(), signerapi.AssemblyRequest{
		RequestID:     "asm-bad-user",
		GroupBytesHex: groupBytesHex,
		Targets: []signerapi.AssemblyTarget{{Kind: signerapi.AssemblyTargetKindGuarded,
			TargetIndex:     0,
			AuthAddress:     guardedAccount,
			UserSignature:   hex.EncodeToString(wrongUserSignature),
			SentrySignature: hex.EncodeToString(sentrySignature),
		}},
	}, group, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("assembleDecoded() error = %#v, want bad request", signErr)
	}
	if !strings.Contains(signErr.Message, "user_signature invalid") {
		t.Fatalf("assembleDecoded() error = %q, want user_signature invalid", signErr.Message)
	}
}

func TestAssembleDecodedGuardedRejectsMismatchedPassthrough(t *testing.T) {
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

func TestSignPreparedSentryComponentsSignsFalconMessages(t *testing.T) {
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
	plan := preparedSentryComponentPlan(t, componentKey)

	result, signErr := signPreparedSentryComponents(context.Background(), plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedSentryComponents() error = %v", signErr)
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
		if err := verify.VerifyFalcon1024(publicKey, plan.Targets[i].Message[:], sigBytes); err != nil {
			t.Fatalf("signature %d does not verify over prepared component message", i)
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedSentryComponentsSignsFalcon1024Messages(t *testing.T) {
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
	plan := preparedSentryComponentPlan(t, componentKey)

	result, signErr := signPreparedSentryComponents(context.Background(), plan, session)
	if signErr != nil {
		t.Fatalf("signPreparedSentryComponents() error = %v", signErr)
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
		if err := verify.VerifyFalcon1024(publicKey, plan.Targets[i].Message[:], sigBytes); err != nil {
			t.Fatalf("signature %d does not verify over prepared component message: %v", i, err)
		}
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after signing: %#v", keyMaterial)
	}
}

func TestSignPreparedSentryComponentsRejectsUserRoleBeforeKeyLoad(t *testing.T) {
	sender := types.Address{9}.String()
	receiver := types.Address{10}.String()
	txn := paymentTransaction(t, sender, receiver, 11)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-user",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	session := &componentKeyTestSession{}

	result, signErr := signPreparedSentryComponents(context.Background(), plan, session)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedSentryComponents() error = %#v, want bad request", signErr)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0 before role rejection", session.calls)
	}
}

func TestSignPreparedSentryComponentsRejectsWrongKeyType(t *testing.T) {
	plan := preparedSentryComponentPlan(t, testFalconComponentSelector(t, 0x11))
	session := &componentKeyTestSession{key: &coresigning.KeyMaterial{Type: "ed25519"}}

	_, err := signPreparedSentryComponents(context.Background(), plan, session)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("signPreparedSentryComponents() error = %#v, want bad request", err)
	}
}

func groupedPaymentTransactions(t *testing.T, sender, receiver string) []types.Transaction {
	t.Helper()
	txns := []types.Transaction{
		paymentTransaction(t, sender, receiver, 1),
		paymentTransaction(t, sender, receiver, 2),
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

func wildcardSentryPolicy(t *testing.T) *policy.Config {
	t.Helper()
	return sentryPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: allow_all_dev
      networks: ["*"]
      sources: ["*"]
      assets: ["*"]
      destinations: ["*"]
`)
}

func sentryRoutePolicy(t *testing.T, source, destination string) *policy.Config {
	t.Helper()
	return sentryPolicyConfigForSigningTest(t, fmt.Sprintf(`
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: allow_test_route
      networks: [testnet]
      sources: [%q]
      assets: ["algo"]
      destinations: [%q]
`, source, destination))
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

func preparedSentryComponentPlan(t *testing.T, componentKey string) *ComponentSignPlan {
	t.Helper()
	sender := types.Address{11}.String()
	receiver := types.Address{12}.String()
	txn := paymentTransaction(t, sender, receiver, 12)
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     "cmp-sentry",
		Role:          signerapi.ComponentSignRoleSentry,
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

type componentUserTestProvider struct {
	family     string
	messages   [][]byte
	signatures [][]byte
}

func (p *componentUserTestProvider) RoutingFamily() string {
	return p.family
}

func (p *componentUserTestProvider) LoadKeyMaterial(_ coresigning.ProviderKey) (*coresigning.KeyMaterial, error) {
	return nil, nil
}

func (p *componentUserTestProvider) SignMessage(_ *coresigning.KeyMaterial, msg []byte) ([]byte, error) {
	msgCopy := append([]byte(nil), msg...)
	signature := append([]byte("user-component-signature:"), msgCopy...)
	p.messages = append(p.messages, msgCopy)
	p.signatures = append(p.signatures, append([]byte(nil), signature...))
	return signature, nil
}

func (p *componentUserTestProvider) ZeroKey(key *coresigning.KeyMaterial) {
	if value, ok := key.Value.([]byte); ok {
		for i := range value {
			value[i] = 0
		}
	}
	key.Type = ""
	key.Value = nil
}

func TestLoadSentryComponentKeyMapsMissingKey(t *testing.T) {
	session := &componentKeyTestSession{err: keystore.ErrKeyNotFound}
	_, _, err := loadSentryComponentKey(context.Background(), session, testFalconComponentSelector(t, 0x22))
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("loadSentryComponentKey() error = %#v, want bad request", err)
	}
}

func TestLoadSentryComponentKeyRejectsMismatchedPublicPrivateKey(t *testing.T) {
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

	_, _, loadErr := loadSentryComponentKey(context.Background(), session, componentKey)
	if loadErr == nil || loadErr.Kind != ErrorInternal {
		t.Fatalf("loadSentryComponentKey() error = %#v, want internal", loadErr)
	}
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Fatalf("key material was not zeroed after mismatch: %#v", keyMaterial)
	}
}

func TestValidateGuardedPassthroughRequiresSignatureAndCanonical(t *testing.T) {
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
	if _, err := validateGuardedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: unsigned}, entry, notHeld); err == nil {
		t.Fatal("unsigned passthrough: expected rejection, got nil")
	}

	// A signed passthrough whose txn matches the canonical entry is accepted.
	signed := hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{0x01}}))
	if _, err := validateGuardedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: signed}, entry, notHeld); err != nil {
		t.Fatalf("signed passthrough: unexpected error %v", err)
	}

	// A passthrough whose sender is a locally-held guarded account is rejected:
	// it must go through component assembly, not passthrough.
	guardedSession := &componentKeyTestSession{keysByAddr: map[string]*coresigning.KeyMaterial{
		sender: {Type: keytypes.GuardedFalcon1024Sentry1024V1},
	}}
	if _, err := validateGuardedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: signed}, entry, guardedSession); err == nil {
		t.Fatal("guarded-account passthrough: expected rejection, got nil")
	}

	// A non-not-found keystore error (e.g. locked session, decrypt failure) must
	// fail closed rather than be treated as a foreign passthrough.
	erroringSession := &componentKeyTestSession{err: fmt.Errorf("session locked")}
	if _, err := validateGuardedPassthrough(context.Background(), signerapi.AssemblyPassthroughItem{TargetIndex: 0, SignedTxnHex: signed}, entry, erroringSession); err == nil {
		t.Fatal("keystore error passthrough: expected fail-closed error, got nil")
	}
}
