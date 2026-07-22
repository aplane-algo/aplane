// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	internallsig "github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func userAutoApproveDefault(v bool) *bool {
	return &v
}

func TestPlannerReturnsTypedBadRequestError(t *testing.T) {
	planner := &Planner{}

	plan, err := planner.PlanGroup("default", signerapi.GroupSignRequest{})
	if plan != nil {
		t.Fatalf("PlanGroup() returned unexpected plan: %#v", plan)
	}
	switch {
	case err == nil:
		t.Fatal("PlanGroup() error = nil, want typed error")
	case err.Kind != ErrorBadRequest:
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	case err.HTTPStatus() != 400:
		t.Fatalf("HTTPStatus() = %d, want 400", err.HTTPStatus())
	}
}

func TestSigningServiceReturnsTypedInternalErrorWhenUnconfigured(t *testing.T) {
	service := &Service{}

	result, err := service.SignGroupWithContext(context.Background(), "default", signerapi.GroupSignRequest{}, nil)
	if result != nil {
		t.Fatalf("SignGroup() returned unexpected result: %#v", result)
	}
	switch {
	case err == nil:
		t.Fatal("SignGroup() error = nil, want typed error")
	case err.Kind != ErrorInternal:
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorInternal)
	case err.HTTPStatus() != 500:
		t.Fatalf("HTTPStatus() = %d, want 500", err.HTTPStatus())
	}
}

func TestEvaluateAutoRejectionRulesStampsTxnIndexes(t *testing.T) {
	nonZeroAddr := types.Address{1}
	txns := []types.Transaction{
		{Header: types.Header{RekeyTo: nonZeroAddr}},
		{Header: types.Header{Fee: 2}},
	}

	err := EvaluateAutoRejectionRules(txns, len(txns), nil, nil, true, &policy.Config{
		RejectForeignRekey: true,
		MaxFeeMicroAlgos:   1,
	}, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want rejection")
	}
	if got := err.Error(); got == "" ||
		!(containsAll(got, []string{"txn 1: [reject_foreign_rekey]", "txn 2: [max_fee_exceeded]"})) {
		t.Fatalf("EvaluateAutoRejectionRules() error = %q, want stamped txn indexes", got)
	}
}

func TestEvaluateAutoRejectionRulesSkipsForeignAndDummyTransactions(t *testing.T) {
	nonZeroAddr := types.Address{1}
	txns := []types.Transaction{
		{Header: types.Header{RekeyTo: nonZeroAddr}}, // foreign slot, should be skipped
		{Header: types.Header{Fee: 1}},               // signer-controlled slot, allowed
		{Header: types.Header{RekeyTo: nonZeroAddr}}, // dummy slot beyond requestCount, should be skipped
	}

	err := EvaluateAutoRejectionRules(txns, 2, nil, map[int]bool{0: true}, true, &policy.Config{
		RejectForeignRekey: true,
	}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("EvaluateAutoRejectionRules() error = %v, want nil when only foreign/dummy slots violate policy", err)
	}
}

func TestEvaluateAutoRejectionRulesAllowsRekeyToLocalAddress(t *testing.T) {
	localAddr := types.Address{1}
	txns := []types.Transaction{
		{Header: types.Header{RekeyTo: localAddr}},
	}

	err := EvaluateAutoRejectionRules(txns, len(txns), nil, nil, false, &policy.Config{
		RejectForeignRekey: true,
	}, nil, map[string]bool{localAddr.String(): true}, nil, nil)
	if err != nil {
		t.Fatalf("EvaluateAutoRejectionRules() error = %v, want nil for local rekey target", err)
	}
}

func TestEvaluateAutoRejectionRulesRespectsThresholdBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *policy.Config
		txn     types.Transaction
		wantErr bool
		wantSub string
	}{
		{
			name: "fee at threshold allowed",
			cfg:  &policy.Config{MaxFeeMicroAlgos: 1000},
			txn: types.Transaction{
				Header: types.Header{Fee: 1000},
			},
		},
		{
			name:    "fee above threshold rejected",
			cfg:     &policy.Config{MaxFeeMicroAlgos: 1000},
			txn:     types.Transaction{Header: types.Header{Fee: 1001}},
			wantErr: true,
			wantSub: "max_fee_exceeded",
		},
		{
			name: "payment at threshold allowed",
			cfg: &policy.Config{
				MaxAlgoPayments:     map[string]uint64{"testnet": 5_000_000},
				GenesisHashResolver: apconfig.DefaultGenesisHashNetworkResolver(),
			},
			txn: types.Transaction{
				Header:           types.Header{GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash)},
				Type:             types.PaymentTx,
				PaymentTxnFields: types.PaymentTxnFields{Amount: 5_000_000},
			},
		},
		{
			name: "payment above threshold rejected",
			cfg: &policy.Config{
				MaxAlgoPayments:     map[string]uint64{"testnet": 5_000_000},
				GenesisHashResolver: apconfig.DefaultGenesisHashNetworkResolver(),
			},
			txn: types.Transaction{
				Header:           types.Header{GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash)},
				Type:             types.PaymentTx,
				PaymentTxnFields: types.PaymentTxnFields{Amount: 6_000_000},
			},
			wantErr: true,
			wantSub: "max_algo_payment_exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EvaluateAutoRejectionRules([]types.Transaction{tt.txn}, 1, nil, nil, false, tt.cfg, nil, nil, nil, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("EvaluateAutoRejectionRules() error = nil, want rejection")
				}
				if !strings.Contains(err.Error(), tt.wantSub) {
					t.Fatalf("EvaluateAutoRejectionRules() error = %q, want %q", err.Error(), tt.wantSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("EvaluateAutoRejectionRules() error = %v, want nil", err)
			}
		})
	}
}

func TestEvaluateAutoRejectionRulesAppliesKeyOverrides(t *testing.T) {
	nonZeroAddr := types.Address{1}
	overrideKey := types.Address{10}.String()
	baseKey := types.Address{11}.String()
	txns := []types.Transaction{
		// Signed by the override key: the override allows asset close.
		{AssetTransferTxnFields: types.AssetTransferTxnFields{AssetCloseTo: nonZeroAddr}},
		// Signed by a different key: inherits identity default (reject).
		{AssetTransferTxnFields: types.AssetTransferTxnFields{AssetCloseTo: nonZeroAddr}},
	}

	cfg := &policy.Config{
		RejectAssetClose: true,
		KeyOverrides: map[string]*policy.Config{
			overrideKey: {RejectAssetClose: false},
		},
	}
	authKeys := []string{overrideKey, baseKey}

	err := EvaluateAutoRejectionRules(txns, len(txns), nil, nil, true, cfg, authKeys, nil, nil, nil)
	if err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want rejection only for non-overridden txn")
	}
	got := err.Error()
	if strings.Contains(got, "txn 1:") {
		t.Errorf("key override should allow asset close on txn 1: %q", got)
	}
	if !strings.Contains(got, "txn 2: [reject_asset_close]") {
		t.Errorf("txn 2 should be rejected by identity default: %q", got)
	}
}

func TestEvaluateAutoRejectionRulesAppliesTransferRouting(t *testing.T) {
	source := types.Address{1}
	allowed := types.Address{2}
	blocked := types.Address{3}
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: allowed_payee
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+allowed.String()+`"]
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: blocked,
			Amount:   1,
		},
	}

	err := EvaluateAutoRejectionRules([]types.Transaction{txn}, 1, nil, nil, false, cfg, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want routing rejection")
	}
	if !strings.Contains(err.Error(), policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("EvaluateAutoRejectionRules() error = %q, want route miss", err.Error())
	}
}

func TestEvaluateAutoRejectionRulesSkipsTransferRoutingForExemptIndex(t *testing.T) {
	source := types.Address{1}
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes: []
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: source,
			Amount:   0,
		},
	}

	err := EvaluateAutoRejectionRules([]types.Transaction{txn}, 1, nil, nil, false, cfg, nil, nil, map[int]bool{0: true}, nil)
	if err != nil {
		t.Fatalf("EvaluateAutoRejectionRules() error = %v, want nil for routing-exempt index", err)
	}
}

func TestEvaluateAutoRejectionRulesUsesTransferRoutingKeyOverrides(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	overrideKey := types.Address{10}.String()
	baseKey := types.Address{11}.String()
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes: []
key_overrides:
  `+overrideKey+`:
    transfer_policy:
      schema_version: 1
      enabled: true
      routes:
        - id: override_allowed
          networks: [testnet]
          sources: ["`+source.String()+`"]
          assets: ["algo"]
          destinations: ["`+dest.String()+`"]
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   1,
		},
	}

	err := EvaluateAutoRejectionRules(
		[]types.Transaction{txn, txn},
		2,
		map[int]bool{},
		map[int]bool{},
		true,
		cfg,
		[]string{overrideKey, baseKey},
		nil,
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want base-policy route miss on second txn")
	}
	got := err.Error()
	if strings.Contains(got, "txn 1:") {
		t.Fatalf("override-routed txn was rejected: %q", got)
	}
	if !strings.Contains(got, "txn 2: ["+policy.TransferRoutingRouteMissRuleID+"]") {
		t.Fatalf("EvaluateAutoRejectionRules() error = %q, want txn 2 route miss", got)
	}
}

func TestEvaluateAutoRejectionRulesSkipsTransferRoutingForPassthroughForeignAndDummySlots(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes: []
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   1,
		},
	}

	err := EvaluateAutoRejectionRules(
		[]types.Transaction{txn, txn, txn, txn},
		3,
		map[int]bool{0: true},
		map[int]bool{1: true},
		true,
		cfg,
		nil,
		nil,
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want route miss on signer-controlled txn")
	}
	got := err.Error()
	if strings.Contains(got, "txn 1:") || strings.Contains(got, "txn 2:") || strings.Contains(got, "txn 4:") {
		t.Fatalf("routing evaluated passthrough, foreign, or dummy slot: %q", got)
	}
	if !strings.Contains(got, "txn 3: ["+policy.TransferRoutingRouteMissRuleID+"]") {
		t.Fatalf("EvaluateAutoRejectionRules() error = %q, want txn 3 route miss", got)
	}
}

func containsAll(s string, wants []string) bool {
	for _, want := range wants {
		if !strings.Contains(s, want) {
			return false
		}
	}
	return true
}

func routingPolicyConfigForSigningTest(t *testing.T, raw string) *policy.Config {
	t.Helper()
	stored, err := policy.ParseStoredConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}
	cfg, err := stored.Apply(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	return cfg
}

func sentryPolicyConfigForSigningTest(t *testing.T, raw string) *policy.Config {
	t.Helper()
	stored, err := policy.ParseStoredSentryConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredSentryConfig() error = %v", err)
	}
	cfg, err := stored.ApplySentry(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("ApplySentry() error = %v", err)
	}
	return cfg
}

func testDigest(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}

type testAuditEntry struct {
	identityID  string
	authAddress string
	txnSender   string
	reason      string
	policyRule  string
}

type testAuditLogger struct {
	approved []testAuditEntry
	rejected []testAuditEntry
}

func (l *testAuditLogger) LogSignApproved(identityID, authAddress, txnSender, details string) {
	l.approved = append(l.approved, testAuditEntry{
		identityID:  identityID,
		authAddress: authAddress,
		txnSender:   txnSender,
		reason:      details,
	})
}

func (l *testAuditLogger) LogSignApprovedWithPolicyRule(identityID, authAddress, txnSender, details, policyRuleID string) {
	l.approved = append(l.approved, testAuditEntry{
		identityID:  identityID,
		authAddress: authAddress,
		txnSender:   txnSender,
		reason:      details,
		policyRule:  policyRuleID,
	})
}

func (l *testAuditLogger) LogSignRejected(identityID, authAddress, txnSender, reason string) {
	l.rejected = append(l.rejected, testAuditEntry{
		identityID:  identityID,
		authAddress: authAddress,
		txnSender:   txnSender,
		reason:      reason,
	})
}

func (l *testAuditLogger) LogSignRejectedWithPolicyRule(identityID, authAddress, txnSender, reason, policyRuleID string) {
	l.rejected = append(l.rejected, testAuditEntry{
		identityID:  identityID,
		authAddress: authAddress,
		txnSender:   txnSender,
		reason:      reason,
		policyRule:  policyRuleID,
	})
}

func TestSignGroupLogsPolicyRejectionToAudit(t *testing.T) {
	nonZeroAddr := types.Address{1}
	txnSender := types.Address{2}
	audit := &testAuditLogger{}
	service := &Service{
		Planner: &Planner{
			VerifySignableKeys: func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, passthroughIndices, foreignIndices map[int]bool) (int, *ServiceError) {
				return 1, nil
			},
			CalculateDummies: func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, txns []types.Transaction, boundedItems []*boundedPlanItem, passthroughIndices, foreignIndices map[int]bool, hasPassthrough, isPreGrouped bool) (int, []int, *ServiceError) {
				return 0, nil, nil
			},
			BuildFinalGroup: func(txns []types.Transaction, dummiesNeeded int, lsigIndices []int, isPreGrouped bool) ([]types.Transaction, []types.Transaction, DummyFeeInfo, bool, *ServiceError) {
				return txns, nil, DummyFeeInfo{}, false, nil
			},
		},
		Approval: &ApprovalService{},
		Executor: &Executor{},
		AuditLog: audit,
		IsUnlocked: func() bool {
			return true
		},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		Policy: &policy.Config{
			RejectForeignRekey: true,
		},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
		}},
	}
	txns := []types.Transaction{
		{Header: types.Header{Sender: txnSender, RekeyTo: nonZeroAddr}},
	}
	plan := &PlanResult{
		AllTxns:               txns,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("signGroupWithPlan() error = nil, want rejection")
	}
	if len(audit.rejected) != 1 {
		t.Fatalf("len(audit.rejected) = %d, want 1", len(audit.rejected))
	}
	entry := audit.rejected[0]
	if entry.identityID != "default" {
		t.Fatalf("identityID = %q, want default", entry.identityID)
	}
	if entry.authAddress != "AUTHADDR" {
		t.Fatalf("authAddress = %q, want AUTHADDR", entry.authAddress)
	}
	if entry.txnSender != txnSender.String() {
		t.Fatalf("txnSender = %q, want %q", entry.txnSender, txnSender.String())
	}
	if !strings.Contains(entry.reason, "policy_engine_rejected") || !strings.Contains(entry.reason, "reject_foreign_rekey") {
		t.Fatalf("reason = %q, want policy rejection details", entry.reason)
	}
}

func TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation(t *testing.T) {
	approvalCalled := false
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove:               userAutoApproveDefault(true),
			GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
			HasClient:                     func(identityID string) bool { return true },
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalCalled = true
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		Policy:                        &policy.Config{RejectForeignRekey: true},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, RekeyTo: types.Address{9}}},
		},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("signGroupWithPlan() error = nil, want policy rejection")
		return
	}
	if err.Kind != ErrorForbidden || !strings.Contains(err.Message, "policy engine rejected request") {
		t.Fatalf("error = %#v, want forbidden policy rejection", err)
	}
	if approvalCalled {
		t.Fatal("approval path was called despite policy rejection")
	}
}

func TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts(t *testing.T) {
	const authAddress = "AUTHADDR"
	sender := types.Address{1}
	selfNoOp := func(fee uint64) types.Transaction {
		return types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      sender,
				Fee:         types.MicroAlgos(fee),
				FirstValid:  1,
				LastValid:   10,
				GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: sender,
				Amount:   0,
			},
		}
	}

	tests := []struct {
		name                  string
		draftTxn              types.Transaction
		finalizedTxn          types.Transaction
		wantKind              ErrorKind
		wantMessage           string
		wantBeforeExecuteCall bool
	}{
		{
			name:                  "draft violates but finalized passes",
			draftTxn:              selfNoOp(policy.SelfNoOpTransferMaxFeeMicroAlgos + 1),
			finalizedTxn:          selfNoOp(policy.SelfNoOpTransferMaxFeeMicroAlgos),
			wantKind:              ErrorUnavailable,
			wantMessage:           "after finalized policy",
			wantBeforeExecuteCall: true,
		},
		{
			name:         "draft passes but finalized violates",
			draftTxn:     selfNoOp(policy.SelfNoOpTransferMaxFeeMicroAlgos),
			finalizedTxn: selfNoOp(policy.SelfNoOpTransferMaxFeeMicroAlgos + 1),
			wantKind:     ErrorForbidden,
			wantMessage:  policy.MaxFeeExceededRuleID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manualApprovalCalled := false
			beforeExecuteCalled := false
			service := &Service{
				Approval: &ApprovalService{
					HasClient: func(identityID string) bool {
						manualApprovalCalled = true
						return false
					},
					RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
						manualApprovalCalled = true
						return false, nil
					},
				},
				Executor:                      &Executor{},
				GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
				IsUnlocked:                    func() bool { return true },
				BeforeExecute: func() (func(), *ServiceError) {
					beforeExecuteCalled = true
					return nil, unavailable("after finalized policy")
				},
				Policy: &policy.Config{
					MaxFeeMicroAlgos:            policy.SelfNoOpTransferMaxFeeMicroAlgos,
					AutoApproveSelfNoOpTransfer: true,
				},
			}

			req := signerapi.GroupSignRequest{
				Requests: []signerapi.SignRequest{{
					AuthAddress: authAddress,
					TxnBytesHex: hex.EncodeToString(msgpack.Encode(tt.draftTxn)),
				}},
			}
			plan := &PlanResult{
				AllTxns:               []types.Transaction{tt.finalizedTxn},
				PassthroughIndices:    map[int]bool{},
				PassthroughSignedTxns: map[int][]byte{},
				ForeignIndices:        map[int]bool{},
				AuthKeyTypes:          []string{"ed25519"},
			}

			result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
			if result != nil {
				t.Fatalf("signGroupWithPlanContext() result = %#v, want nil", result)
			}
			if err == nil {
				t.Fatal("signGroupWithPlanContext() error = nil")
				return
			}
			if err.Kind != tt.wantKind || !strings.Contains(err.Message, tt.wantMessage) {
				t.Fatalf("error = %#v, want kind %q containing %q", err, tt.wantKind, tt.wantMessage)
			}
			if beforeExecuteCalled != tt.wantBeforeExecuteCall {
				t.Fatalf("BeforeExecute called = %v, want %v", beforeExecuteCalled, tt.wantBeforeExecuteCall)
			}
			if manualApprovalCalled {
				t.Fatal("manual approval path was called")
			}
		})
	}
}

func TestSignGroupWithPlanAutoApproveSelfNoOpTransferSkipsManualReview(t *testing.T) {
	approvalPathCalled := false
	beforeExecuteCalled := false
	addr := types.Address{1}
	service := &Service{
		Approval: &ApprovalService{
			HasClient: func(identityID string) bool {
				approvalPathCalled = true
				return false
			},
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalPathCalled = true
				return false, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("after auto approval")
		},
		Policy: &policy.Config{AutoApproveSelfNoOpTransfer: true},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender: addr,
				Fee:    types.MicroAlgos(policy.SelfNoOpTransferMaxFeeMicroAlgos),
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: addr,
				Amount:   0,
			},
		}},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil || !strings.Contains(err.Message, "after auto approval") {
		t.Fatalf("signGroupWithPlan() error = %#v, want before-execute failure after auto approval", err)
	}
	if approvalPathCalled {
		t.Fatal("manual approval path was called despite self no-op auto-approval")
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called after self no-op auto-approval")
	}
}

func TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove(t *testing.T) {
	approvalCalled := false
	beforeExecuteCalled := false
	var gotViolations []signerapproval.Violation
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove:               userAutoApproveDefault(true),
			GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
			HasClient:                     func(identityID string) bool { return true },
			KnownAddresses: func(identityID string) map[string]bool {
				return nil
			},
			EncodeTxnToHex: func(txn types.Transaction) string {
				return hex.EncodeToString(msgpack.Encode(txn))
			},
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalCalled = true
				gotViolations = violations
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("after forced review")
		},
		Policy: &policy.Config{AlwaysReviewWarnings: true},
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    types.MicroAlgos(1_000_001),
		},
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns:               []types.Transaction{txn},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil || !strings.Contains(err.Message, "after forced review") {
		t.Fatalf("signGroupWithPlan() error = %#v, want before-execute failure after forced review", err)
	}
	if !approvalCalled {
		t.Fatal("manual approval path was not called for always-review warning")
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called after approval")
	}
	if len(gotViolations) != 1 || gotViolations[0].Field != "Fee" {
		t.Fatalf("violations = %#v, want fee warning", gotViolations)
	}
}

func TestSignGroupWithPlanDoesNotReevaluatePolicyAfterApproval(t *testing.T) {
	approvalCalled := false
	beforeExecuteCalled := false
	var service *Service
	service = &Service{
		Approval: &ApprovalService{
			GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
			HasClient:                     func(identityID string) bool { return true },
			KnownAddresses:                func(identityID string) map[string]bool { return nil },
			EncodeTxnToHex: func(txn types.Transaction) string {
				return hex.EncodeToString(msgpack.Encode(txn))
			},
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalCalled = true
				service.Policy = &policy.Config{RejectForeignRekey: true}
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, unavailable("after approval")
		},
		Policy: &policy.Config{AlwaysReviewWarnings: true},
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:  types.Address{1},
			Fee:     types.MicroAlgos(1_000_001),
			RekeyTo: types.Address{9},
		},
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns:               []types.Transaction{txn},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil || !strings.Contains(err.Message, "after approval") {
		t.Fatalf("signGroupWithPlan() error = %#v, want before-execute failure after approval", err)
	}
	if !approvalCalled {
		t.Fatal("manual approval path was not called")
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called after approval")
	}
}

func TestSignGroupWithPlanTransferRoutingReviewOverridesUserAutoApprove(t *testing.T) {
	approvalCalled := false
	beforeExecuteCalled := false
	var gotViolations []signerapproval.Violation
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: review_payee
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
      limits:
        review_above: 10
`)
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove:               userAutoApproveDefault(true),
			GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
			HasClient:                     func(identityID string) bool { return true },
			KnownAddresses:                func(identityID string) map[string]bool { return nil },
			EncodeTxnToHex: func(txn types.Transaction) string {
				return hex.EncodeToString(msgpack.Encode(txn))
			},
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalCalled = true
				gotViolations = violations
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("after routing review")
		},
		Policy: cfg,
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   11,
		},
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns:               []types.Transaction{txn},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil || !strings.Contains(err.Message, "after routing review") {
		t.Fatalf("signGroupWithPlan() error = %#v, want before-execute failure after routing review", err)
	}
	if !approvalCalled {
		t.Fatal("manual approval path was not called for transfer routing review")
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called after transfer routing approval")
	}
	if len(gotViolations) != 0 {
		t.Fatalf("violations = %#v, want no warning violations for routing-only review", gotViolations)
	}
}

func TestSignGroupWithPlanAutoApproveSelfNoOpTransferAllowsSignerDummies(t *testing.T) {
	approvalPathCalled := false
	beforeExecuteCalled := false
	addr := types.Address{1}
	dummyAddr, err := internallsig.DummyAddress()
	if err != nil {
		t.Fatalf("DummyAddress() error = %v", err)
	}

	service := &Service{
		Approval: &ApprovalService{
			HasClient: func(identityID string) bool {
				approvalPathCalled = true
				return false
			},
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalPathCalled = true
				return false, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("after auto approval")
		},
		Policy: &policy.Config{AutoApproveSelfNoOpTransfer: true},
	}

	group := types.Digest{9}
	genesisHash := types.Digest{7}
	dummies := signerDummyTxnsForTest(t, dummyAddr, group, genesisHash, 3)
	plan := &PlanResult{
		AllTxns: append([]types.Transaction{{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      addr,
				Fee:         types.MicroAlgos(policy.SelfNoOpTransferMaxFeeMicroAlgos + 3*policy.SelfNoOpTransferMaxFeeMicroAlgos),
				FirstValid:  100,
				LastValid:   200,
				GenesisID:   "localnet-v1",
				GenesisHash: genesisHash,
				Group:       group,
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: addr,
				Amount:   0,
			},
		}}, dummies...),
		DummyTxns:             dummies,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
		LsigIndices:           []int{0},
		DummiesNeeded:         len(dummies),
		FeeInfo:               DummyFeeInfo{TotalFees: 3 * policy.SelfNoOpTransferMaxFeeMicroAlgos, LSigCount: 1},
		AuthKeyTypes:          []string{"aplane.falcon1024.v1"},
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}

	result, signErr := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if signErr == nil || !strings.Contains(signErr.Message, "after auto approval") {
		t.Fatalf("signGroupWithPlan() error = %#v, want before-execute failure after auto approval", signErr)
	}
	if approvalPathCalled {
		t.Fatal("manual approval path was called despite self no-op auto-approval with signer dummies")
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called after self no-op auto-approval with signer dummies")
	}
}

func TestSelfNoOpTransferPlanAutoApprovalUsesActualDummyFees(t *testing.T) {
	addr := types.Address{1}
	dummyAddr, err := internallsig.DummyAddress()
	if err != nil {
		t.Fatalf("DummyAddress() error = %v", err)
	}
	group := types.Digest{9}
	genesisHash := types.Digest{7}
	dummies := signerDummyTxnsForTest(t, dummyAddr, group, genesisHash, 2)
	plan := &PlanResult{
		AllTxns: append([]types.Transaction{{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      addr,
				Fee:         types.MicroAlgos(policy.SelfNoOpTransferMaxFeeMicroAlgos + 1500),
				FirstValid:  100,
				LastValid:   200,
				GenesisID:   "localnet-v1",
				GenesisHash: genesisHash,
				Group:       group,
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: addr,
				Amount:   0,
			},
		}}, dummies...),
		DummyTxns:     dummies,
		LsigIndices:   []int{0},
		DummiesNeeded: len(dummies),
		FeeInfo:       DummyFeeInfo{TotalFees: 1500, LSigCount: 1},
	}

	if !matchesSelfNoOpTransferPlanAutoApproval(plan, plan.AllTxns) {
		t.Fatal("matchesSelfNoOpTransferPlanAutoApproval() = false, want true for actual dummy fee total below cap")
	}
}

func TestSignGroupWithPlanAutoApproveASAZeroSelfTransferSkipsManualReview(t *testing.T) {
	approvalPathCalled := false
	beforeExecuteCalled := false
	addr := types.Address{1}
	service := &Service{
		Approval: &ApprovalService{
			HasClient: func(identityID string) bool {
				approvalPathCalled = true
				return false
			},
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalPathCalled = true
				return false, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("after auto approval")
		},
		Policy: &policy.Config{AutoApproveSelfNoOpTransfer: true},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{{
			Type: types.AssetTransferTx,
			Header: types.Header{
				Sender: addr,
				Fee:    types.MicroAlgos(policy.SelfNoOpTransferMaxFeeMicroAlgos),
			},
			AssetTransferTxnFields: types.AssetTransferTxnFields{
				XferAsset:     123,
				AssetReceiver: addr,
				AssetAmount:   0,
			},
		}},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil || !strings.Contains(err.Message, "after auto approval") {
		t.Fatalf("signGroupWithPlan() error = %#v, want before-execute failure after auto approval", err)
	}
	if approvalPathCalled {
		t.Fatal("manual approval path was called despite ASA self no-op auto-approval")
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called after ASA self no-op auto-approval")
	}
}

func TestSignGroupWithPlanSelfNoOpAutoApproveFallsBackForUnexpectedDummy(t *testing.T) {
	beforeExecuteCalled := false
	addr := types.Address{1}
	dummyAddr, err := internallsig.DummyAddress()
	if err != nil {
		t.Fatalf("DummyAddress() error = %v", err)
	}
	service := &Service{
		Approval: &ApprovalService{
			HasClient: func(identityID string) bool { return false },
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("should not execute")
		},
		Policy: &policy.Config{AutoApproveSelfNoOpTransfer: true},
	}

	group := types.Digest{9}
	genesisHash := types.Digest{7}
	dummies := signerDummyTxnsForTest(t, dummyAddr, group, genesisHash, 3)
	dummies[1].Sender = types.Address{2}
	plan := &PlanResult{
		AllTxns: append([]types.Transaction{{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      addr,
				Fee:         types.MicroAlgos(policy.SelfNoOpTransferMaxFeeMicroAlgos + 3*policy.SelfNoOpTransferMaxFeeMicroAlgos),
				FirstValid:  100,
				LastValid:   200,
				GenesisID:   "localnet-v1",
				GenesisHash: genesisHash,
				Group:       group,
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: addr,
				Amount:   0,
			},
		}}, dummies...),
		DummyTxns:             dummies,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
		LsigIndices:           []int{0},
		DummiesNeeded:         len(dummies),
		FeeInfo:               DummyFeeInfo{TotalFees: 3 * policy.SelfNoOpTransferMaxFeeMicroAlgos, LSigCount: 1},
		AuthKeyTypes:          []string{"aplane.falcon1024.v1"},
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}

	result, signErr := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if signErr == nil || signErr.Kind != ErrorUnavailable || !strings.Contains(signErr.Message, "no apadmin connected") {
		t.Fatalf("signGroupWithPlan() error = %#v, want operator fallback", signErr)
	}
	if beforeExecuteCalled {
		t.Fatal("BeforeExecute was called even though signer dummy predicate failed")
	}
}

func TestSignGroupWithPlanSelfNoOpAutoApproveFallsBackWhenPredicateFails(t *testing.T) {
	beforeExecuteCalled := false
	addr := types.Address{1}
	service := &Service{
		Approval: &ApprovalService{
			HasClient: func(identityID string) bool { return false },
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("should not execute")
		},
		Policy: &policy.Config{AutoApproveSelfNoOpTransfer: true},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender: addr,
				Fee:    types.MicroAlgos(policy.SelfNoOpTransferMaxFeeMicroAlgos + 1),
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: addr,
				Amount:   0,
			},
		}},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorUnavailable || !strings.Contains(err.Message, "no apadmin connected") {
		t.Fatalf("signGroupWithPlan() error = %#v, want operator fallback", err)
	}
	if beforeExecuteCalled {
		t.Fatal("BeforeExecute was called even though self no-op predicate failed")
	}
}

func signerDummyTxnsForTest(t *testing.T, dummyAddr types.Address, group, genesisHash types.Digest, count int) []types.Transaction {
	t.Helper()

	txns := make([]types.Transaction, count)
	for i := range txns {
		txns[i] = types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      dummyAddr,
				Fee:         0,
				FirstValid:  100,
				LastValid:   200,
				GenesisID:   "localnet-v1",
				GenesisHash: genesisHash,
				Group:       group,
				Note:        []byte{byte(i)},
			},
			PaymentTxnFields: types.PaymentTxnFields{
				Receiver: dummyAddr,
				Amount:   0,
			},
		}
	}
	return txns
}

func TestSignGroupWithPlanRejectsNetworkScopedAlgoLimit(t *testing.T) {
	approvalCalled := false
	service := &Service{
		Approval: &ApprovalService{
			HasClient: func(identityID string) bool { return true },
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				approvalCalled = true
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		Policy: &policy.Config{
			MaxAlgoPayments:     map[string]uint64{"testnet": 1_000_000},
			GenesisHashResolver: apconfig.DefaultGenesisHashNetworkResolver(),
		},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{
				Header: types.Header{
					Sender:      types.Address{1},
					GenesisHash: testDigest(t, apconfig.AlgorandTestnetGenesisHash),
				},
				Type: types.PaymentTx,
				PaymentTxnFields: types.PaymentTxnFields{
					Amount: 2_000_000,
				},
			},
		},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("signGroupWithPlan() error = nil, want policy rejection")
		return
	}
	if err.Kind != ErrorForbidden || !strings.Contains(err.Message, "max_algo_payment_exceeded") {
		t.Fatalf("error = %#v, want max ALGO policy rejection", err)
	}
	if approvalCalled {
		t.Fatal("approval path was called despite policy rejection")
	}
}

func TestSignGroupWithPlanStopsBeforeExecute(t *testing.T) {
	beforeExecuteCalled := false
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: userAutoApproveDefault(true),
		},
		Executor: &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string {
			return "txn"
		},
		IsUnlocked: func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return nil, forbidden("identity is decommissioned")
		},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}},
		},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("signGroupWithPlan() error = nil, want before-execute failure")
		return
	}
	if err.Kind != ErrorForbidden || !strings.Contains(err.Message, "identity is decommissioned") {
		t.Fatalf("error = %#v, want decommissioned forbidden", err)
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called")
	}
}

func TestSignGroupWithPlanReleasesBeforeExecuteLeaseAfterExecution(t *testing.T) {
	beforeExecuteCalled := false
	releaseCalled := false
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: userAutoApproveDefault(true),
		},
		Executor: &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string {
			return "txn"
		},
		IsUnlocked: func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			beforeExecuteCalled = true
			return func() {
				releaseCalled = true
			}, nil
		},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			SignedTxnHex: "cafe",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}},
		},
		PassthroughIndices:    map[int]bool{0: true},
		PassthroughSignedTxns: map[int][]byte{0: {0xca, 0xfe}},
		ForeignIndices:        map[int]bool{},
		HasPassthrough:        true,
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if err != nil {
		t.Fatalf("signGroupWithPlan() error = %#v, want nil", err)
	}
	if result == nil || len(result.Signed) != 1 || result.Signed[0] != "cafe" {
		t.Fatalf("signGroupWithPlan() result = %#v, want passthrough signed txn", result)
	}
	if !beforeExecuteCalled {
		t.Fatal("BeforeExecute was not called")
	}
	if !releaseCalled {
		t.Fatal("BeforeExecute release was not called after execution")
	}
}

func TestSignGroupWithPlanUserAutoApproveDecommissionBeforeExecute(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            "default",
		Authenticator: auth.NewTokenAuthenticator("tok"),
	})
	ir.SetUnlocked()

	beforeExecuteStarted := make(chan struct{})
	proceed := make(chan struct{})
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: userAutoApproveDefault(true),
		},
		Executor: &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string {
			return "txn"
		},
		IsUnlocked: func() bool {
			return ir.IsUnlocked() && !ir.IsDecommissioned()
		},
		BeforeExecute: func() (func(), *ServiceError) {
			close(beforeExecuteStarted)
			<-proceed
			release, err := ir.BeginOperation()
			if err != nil {
				return nil, forbidden(err.Error())
			}
			return release, nil
		},
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			SignedTxnHex: "cafe",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}},
		},
		PassthroughIndices:    map[int]bool{0: true},
		PassthroughSignedTxns: map[int][]byte{0: {0xca, 0xfe}},
		ForeignIndices:        map[int]bool{},
		HasPassthrough:        true,
	}

	type signResult struct {
		result *SignGroupResult
		err    *ServiceError
	}
	done := make(chan signResult, 1)
	go func() {
		result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
		done <- signResult{result: result, err: err}
	}()

	select {
	case <-beforeExecuteStarted:
	case <-time.After(time.Second):
		t.Fatal("BeforeExecute was not reached")
	}

	if err := ir.Decommission(); err != nil {
		t.Fatalf("Decommission() error = %v", err)
	}
	close(proceed)

	select {
	case got := <-done:
		if got.result != nil {
			t.Fatalf("signGroupWithPlan() result = %#v, want nil", got.result)
		}
		if got.err == nil {
			t.Fatal("signGroupWithPlan() error = nil, want decommissioned failure")
		}
		if got.err.Kind != ErrorForbidden || !strings.Contains(got.err.Message, "identity is decommissioned") {
			t.Fatalf("error = %#v, want decommissioned forbidden", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("signGroupWithPlan() did not return after decommission")
	}
}

func TestLogPolicyRejectionsSkipsPassthroughAndForeign(t *testing.T) {
	audit := &testAuditLogger{}
	service := &Service{AuditLog: audit}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{AuthAddress: "A"},
			{SignedTxnHex: "signed"},
			{TxnBytesHex: "foreign"},
		},
	}
	plan := &PlanResult{
		PassthroughIndices: map[int]bool{1: true},
		ForeignIndices:     map[int]bool{2: true},
	}
	txns := []types.Transaction{
		{Header: types.Header{Sender: types.Address{1}}},
		{Header: types.Header{Sender: types.Address{2}}},
		{Header: types.Header{Sender: types.Address{3}}},
	}

	service.logPolicyRejections("default", req, plan, txns, "policy_engine_rejected: test")
	if len(audit.rejected) != 1 {
		t.Fatalf("len(audit.rejected) = %d, want 1", len(audit.rejected))
	}
	if audit.rejected[0].authAddress != "A" {
		t.Fatalf("authAddress = %q, want A", audit.rejected[0].authAddress)
	}
}

func TestLogSuccessfulSignaturesSkipsPassthroughAndForeign(t *testing.T) {
	audit := &testAuditLogger{}
	service := &Service{AuditLog: audit}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{AuthAddress: "A"},
			{SignedTxnHex: "signed"},
			{TxnBytesHex: "foreign"},
		},
	}
	plan := &PlanResult{
		PassthroughIndices: map[int]bool{1: true},
		ForeignIndices:     map[int]bool{2: true},
	}
	txns := []types.Transaction{
		{Header: types.Header{Sender: types.Address{1}}},
		{Header: types.Header{Sender: types.Address{2}}},
		{Header: types.Header{Sender: types.Address{3}}},
	}

	service.logSuccessfulSignatures("default", req, plan, txns, "")
	if len(audit.approved) != 1 {
		t.Fatalf("len(audit.approved) = %d, want 1", len(audit.approved))
	}
	if audit.approved[0].authAddress != "A" {
		t.Fatalf("authAddress = %q, want A", audit.approved[0].authAddress)
	}
	if audit.approved[0].txnSender != txns[0].Sender.String() {
		t.Fatalf("txnSender = %q, want %q", audit.approved[0].txnSender, txns[0].Sender.String())
	}
}

func TestLogSuccessfulSignaturesIncludesForcedReviewRule(t *testing.T) {
	audit := &testAuditLogger{}
	service := &Service{AuditLog: audit}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{AuthAddress: "A"}},
	}
	plan := &PlanResult{
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
	}
	txns := []types.Transaction{{Header: types.Header{Sender: types.Address{1}}}}

	service.logSuccessfulSignatures("default", req, plan, txns, policy.ReviewAlgoPaymentExceededRuleID)
	if len(audit.approved) != 1 {
		t.Fatalf("len(audit.approved) = %d, want 1", len(audit.approved))
	}
	if got := audit.approved[0].policyRule; got != policy.ReviewAlgoPaymentExceededRuleID {
		t.Fatalf("policyRule = %q, want %q", got, policy.ReviewAlgoPaymentExceededRuleID)
	}
}

func TestSignGroupWithPlanUsesSingleTxnApprovalForServerAddedDummies(t *testing.T) {
	var (
		gotDescription string
		gotFirstValid  uint64
		gotLastValid   uint64
	)

	service := &Service{
		Approval: &ApprovalService{
			HasClient:                     func(identityID string) bool { return true },
			KnownAddresses:                func(identityID string) map[string]bool { return nil },
			GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
			EncodeTxnToHex:                func(txn types.Transaction) string { return "deadbeef" },
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				gotDescription = description
				gotFirstValid = firstValid
				gotLastValid = lastValid
				return false, nil
			},
		},
		Executor: &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string {
			return "txn"
		},
		IsUnlocked: func() bool { return true },
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, FirstValid: 100, LastValid: 200}},
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}, FirstValid: 100, LastValid: 200}},
		},
		DummiesNeeded:         1,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("signGroupWithPlan() error = nil, want operator rejection")
		return
	}
	if !strings.Contains(err.Message, "Transaction rejected by operator") {
		t.Fatalf("unexpected error message: %q", err.Message)
	}
	if !strings.HasPrefix(gotDescription, "[TXN APPROVAL]\n") {
		t.Fatalf("approval description = %q, want txn approval prefix", gotDescription)
	}
	if !strings.Contains(gotDescription, "[MODIFIED: Fee adjusted for dummy transactions]") {
		t.Fatalf("approval description = %q, want dummy modification note", gotDescription)
	}
	if gotFirstValid != 100 || gotLastValid != 200 {
		t.Fatalf("approval window = (%d, %d), want (100, 200)", gotFirstValid, gotLastValid)
	}
}

func TestSignGroupWithPlanUsesIntersectedValidityWindowForGroups(t *testing.T) {
	var (
		gotTxnSender   string
		gotDescription string
		gotFirstValid  uint64
		gotLastValid   uint64
	)

	service := &Service{
		Approval: &ApprovalService{
			HasClient:      func(identityID string) bool { return true },
			KnownAddresses: func(identityID string) map[string]bool { return nil },
			RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				gotTxnSender = txnSender
				gotDescription = description
				gotFirstValid = firstValid
				gotLastValid = lastValid
				return false, nil
			},
		},
		Executor: &Executor{},
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string {
			return "txn"
		},
		IsUnlocked: func() bool { return true },
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{AuthAddress: "AUTHADDR1", TxnBytesHex: "deadbeef"},
			{AuthAddress: "AUTHADDR2", TxnBytesHex: "cafebabe"},
		},
	}
	plan := &PlanResult{
		AllTxns: []types.Transaction{
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, FirstValid: 100, LastValid: 300}},
			{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}, FirstValid: 140, LastValid: 220}},
		},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	result, err := service.signGroupWithPlanContext(context.Background(), "default", req, nil, plan)
	if result != nil {
		t.Fatalf("signGroupWithPlan() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("signGroupWithPlan() error = nil, want operator rejection")
		return
	}
	if !strings.Contains(err.Message, "Group request rejected by operator") {
		t.Fatalf("unexpected error message: %q", err.Message)
	}
	if !strings.HasPrefix(gotDescription, "[GROUP APPROVAL]\n") {
		t.Fatalf("approval description = %q, want group approval prefix", gotDescription)
	}
	if gotTxnSender != "GROUP(2 txns)" {
		t.Fatalf("txnSender = %q, want GROUP(2 txns)", gotTxnSender)
	}
	if gotFirstValid != 140 || gotLastValid != 220 {
		t.Fatalf("approval window = (%d, %d), want (140, 220)", gotFirstValid, gotLastValid)
	}
}
