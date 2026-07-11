// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// cloningComponentSession returns a fresh key-material copy per load, matching
// the real keystore contract that each caller owns (and zeroes) its copy.
type cloningComponentSession struct {
	address string
	fresh   func() *coresigning.KeyMaterial
	calls   int
}

func (s *cloningComponentSession) GetKeyWithContext(_ context.Context, address string) (*coresigning.KeyMaterial, error) {
	s.calls++
	if address != s.address {
		return nil, keystore.ErrKeyNotFound
	}
	return s.fresh(), nil
}

func guardedGateKeyMaterial(baseKeyType string) func() *coresigning.KeyMaterial {
	return func() *coresigning.KeyMaterial {
		return &coresigning.KeyMaterial{
			Type:        keytypes.GuardedFalcon1024SentryEd25519V1,
			Category:    keys.CategoryDSALsig,
			BaseKeyType: baseKeyType,
			Bytecode:    []byte{0x01, 0x02, 0x03},
			Value:       []byte{0xaa, 0xbb, 0xcc},
		}
	}
}

type componentGatePrompt struct {
	approve     bool
	calls       int
	address     string
	description string
}

func (p *componentGatePrompt) approvalService(audit *testAuditLogger) *ApprovalService {
	return &ApprovalService{
		AuditLog:       audit,
		HasClient:      func(string) bool { return true },
		KnownAddresses: func(string) map[string]bool { return nil },
		RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			p.calls++
			p.address = address
			p.description = description
			return p.approve, nil
		},
	}
}

func newComponentGateService(audit *testAuditLogger, approval *ApprovalService, cfg *policy.Config) *Service {
	return &Service{
		Approval:                      approval,
		AuditLog:                      audit,
		IsUnlocked:                    func() bool { return true },
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		Policy:                        cfg,
	}
}

func userComponentGateRequest(t *testing.T, sender string, txns []types.Transaction, targetIndices []int) signerapi.ComponentSignRequest {
	t.Helper()
	groupBytesHex := make([]string, len(txns))
	for i, txn := range txns {
		groupBytesHex[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	return signerapi.ComponentSignRequest{
		RequestID:     "cmp-gate-test",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: groupBytesHex,
		TargetIndices: targetIndices,
	}
}

func TestSignComponentUserRoleRejectedBySignerPolicy(t *testing.T) {
	provider := &componentUserTestProvider{family: "test.component-gate-policy-reject.v1"}
	coresigning.Register(provider)

	sender := types.Address{21}.String()
	receiver := types.Address{22}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), &policy.Config{MaxFeeMicroAlgos: 1})
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	_, err := svc.SignComponentWithContext(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), nil)
	if err == nil {
		t.Fatal("SignComponentWithContext() error = nil, want session required")
	}

	_, err = svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponent error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "policy engine rejected request") {
		t.Fatalf("SignComponent error = %q, want policy engine rejection", err.Message)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 for policy rejection", prompt.calls)
	}
	if session.calls != 1 {
		t.Fatalf("session calls = %d, want preflight only", session.calls)
	}
	if len(audit.rejected) != 2 {
		t.Fatalf("rejected audit entries = %#v, want 2", audit.rejected)
	}
	for _, entry := range audit.rejected {
		if entry.authAddress != sender || !strings.HasPrefix(entry.reason, "policy_engine_rejected: ") {
			t.Fatalf("rejected audit entry = %#v, want guarded key and policy_engine_rejected prefix", entry)
		}
	}
	if len(provider.messages) != 0 {
		t.Fatalf("provider messages = %d, want no signatures after rejection", len(provider.messages))
	}
}

func TestSignComponentUserRoleOperatorApproves(t *testing.T) {
	provider := &componentUserTestProvider{family: "test.component-gate-operator-approve.v1"}
	coresigning.Register(provider)

	sender := types.Address{23}.String()
	receiver := types.Address{24}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	result, err := svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err != nil {
		t.Fatalf("SignComponent error = %v", err)
	}
	if len(result.Signatures) != 2 {
		t.Fatalf("Signatures len = %d, want 2", len(result.Signatures))
	}
	if prompt.calls != 1 {
		t.Fatalf("prompt calls = %d, want 1", prompt.calls)
	}
	if prompt.address != sender {
		t.Fatalf("prompt address = %q, want guarded account %q", prompt.address, sender)
	}
	if !strings.Contains(prompt.description, "[GUARDED COMPONENT APPROVAL]") || !strings.Contains(prompt.description, "GUARDED TARGET") {
		t.Fatalf("prompt description = %q, want guarded component markers", prompt.description)
	}
	if len(audit.approved) != 2 {
		t.Fatalf("approved audit entries = %#v, want 2", audit.approved)
	}
	for _, entry := range audit.approved {
		if entry.authAddress != sender || !strings.Contains(entry.reason, "user component signature target") {
			t.Fatalf("approved audit entry = %#v, want guarded key user-component details", entry)
		}
	}
}

func TestSignComponentUserRoleOperatorDenies(t *testing.T) {
	provider := &componentUserTestProvider{family: "test.component-gate-operator-deny.v1"}
	coresigning.Register(provider)

	sender := types.Address{25}.String()
	receiver := types.Address{26}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	_, err := svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponent error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "rejected by operator") {
		t.Fatalf("SignComponent error = %q, want operator rejection", err.Message)
	}
	if session.calls != 1 {
		t.Fatalf("session calls = %d, want preflight only", session.calls)
	}
	if len(audit.rejected) != 2 {
		t.Fatalf("rejected audit entries = %#v, want 2", audit.rejected)
	}
	for _, entry := range audit.rejected {
		if entry.reason != "component_rejected_by_operator" {
			t.Fatalf("rejected audit entry = %#v, want component_rejected_by_operator", entry)
		}
	}
	if len(provider.messages) != 0 {
		t.Fatalf("provider messages = %d, want no signatures after denial", len(provider.messages))
	}
}

func TestSignComponentUserRoleUserAutoApproveSkipsPrompt(t *testing.T) {
	provider := &componentUserTestProvider{family: "test.component-gate-user-auto.v1"}
	coresigning.Register(provider)

	sender := types.Address{27}.String()
	receiver := types.Address{28}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	approval := prompt.approvalService(audit)
	approval.UserAutoApprove = userAutoApproveDefault(true)
	svc := newComponentGateService(audit, approval, nil)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	result, err := svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err != nil {
		t.Fatalf("SignComponent error = %v", err)
	}
	if len(result.Signatures) != 2 {
		t.Fatalf("Signatures len = %d, want 2", len(result.Signatures))
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 under user auto-approve", prompt.calls)
	}
}

func TestSignComponentUserRoleForeignRekeyLegForcesReview(t *testing.T) {
	provider := &componentUserTestProvider{family: "test.component-gate-foreign-review.v1"}
	coresigning.Register(provider)

	sender := types.Address{29}.String()
	receiver := types.Address{30}.String()
	txns := []types.Transaction{
		paymentTransaction(t, sender, receiver, 1),
		paymentTransaction(t, receiver, receiver, 0),
	}
	txns[1].RekeyTo = types.Address{31}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txns[0].Group = groupID
	txns[1].Group = groupID

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	approval := prompt.approvalService(audit)
	approval.UserAutoApprove = userAutoApproveDefault(true)
	svc := newComponentGateService(audit, approval, &policy.Config{})
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	result, svcErr := svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0}), session)
	if svcErr != nil {
		t.Fatalf("SignComponent error = %v", svcErr)
	}
	if len(result.Signatures) != 1 {
		t.Fatalf("Signatures len = %d, want 1", len(result.Signatures))
	}
	if prompt.calls != 1 {
		t.Fatalf("prompt calls = %d, want forced review despite user auto-approve", prompt.calls)
	}
	if len(audit.approved) != 1 || audit.approved[0].policyRule != policy.AlwaysReviewWarningsRuleID {
		t.Fatalf("approved audit entries = %#v, want always-review rule ID", audit.approved)
	}
}

func TestSignComponentUserRoleWithoutAdminClientFailsClosed(t *testing.T) {
	sender := types.Address{32}.String()
	receiver := types.Address{33}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	approval := prompt.approvalService(audit)
	approval.HasClient = func(string) bool { return false }
	svc := newComponentGateService(audit, approval, nil)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial("test.component-gate-no-client.v1")}

	_, err := svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorUnavailable {
		t.Fatalf("SignComponent error = %#v, want unavailable", err)
	}
	if !strings.Contains(err.Message, "no apadmin connected") {
		t.Fatalf("SignComponent error = %q, want no apadmin connected", err.Message)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 without admin client", prompt.calls)
	}
}

func TestSignComponentUserRolePreflightRejectsUnknownKeyBeforePrompt(t *testing.T) {
	sender := types.Address{34}.String()
	receiver := types.Address{35}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil)
	session := &cloningComponentSession{address: "other", fresh: guardedGateKeyMaterial("test.component-gate-preflight.v1")}

	_, err := svc.signComponentWithSession(componentGateContext(), "default", userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("SignComponent error = %#v, want bad request", err)
	}
	if !strings.Contains(err.Message, "not found") {
		t.Fatalf("SignComponent error = %q, want key not found", err.Message)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 when preflight fails", prompt.calls)
	}
}

func TestGateUserComponentSigningSimulationSkipsPrompt(t *testing.T) {
	sender := types.Address{36}.String()
	receiver := types.Address{37}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	plan, err := PrepareComponentSigning(userComponentGateRequest(t, sender, txns, []int{0, 1}))
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	svc := newComponentGateService(audit, prompt.approvalService(audit), &policy.Config{})

	ruleID, gateErr := svc.gateUserComponentSigning(componentGateContext(), "default", plan, true)
	if gateErr != nil {
		t.Fatalf("gateUserComponentSigning(simulation) error = %v", gateErr)
	}
	if ruleID != "" {
		t.Fatalf("gateUserComponentSigning(simulation) ruleID = %q, want empty", ruleID)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 for simulation", prompt.calls)
	}
}

func componentGateContext() context.Context {
	return context.Background()
}
