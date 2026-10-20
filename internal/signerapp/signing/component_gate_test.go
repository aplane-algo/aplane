// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestBuildComponentApprovalDescriptionPreservesABIMethod(t *testing.T) {
	selector, err := appspec.SignatureSelector("increment(uint64)void")
	if err != nil {
		t.Fatal(err)
	}
	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
			ApplicationID: 123, OnCompletion: types.NoOpOC,
			ApplicationArgs: [][]byte{selector},
		}},
	}
	plan := &ComponentSignPlan{Requests: []signerapi.SignRequest{{
		AppCallInfo: &signerapi.AppCallInfo{Mode: "abi", Method: "increment(uint64)void"},
	}}}
	description, _, _ := buildComponentApprovalDescription(
		plan,
		[]types.Transaction{txn},
		map[int]bool{0: true},
		func(types.Transaction) string { return "App Call: #123 (NoOp)" },
	)
	if !strings.Contains(description, "Method: increment(uint64)void") {
		t.Fatalf("component approval description lost ABI method:\n%s", description)
	}
}

func TestGateUserComponentSigningExcludesFrozenDummySuffix(t *testing.T) {
	sender := types.Address{19}.String()
	receiver := types.Address{20}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	// A rekey on the suffix would force manual review if the gate accidentally
	// counted signer-added dummies as caller-supplied originals.
	txns[1].RekeyTo = types.Address{21}
	for i := range txns {
		txns[i].Group = types.Digest{}
	}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatal(err)
	}
	for i := range txns {
		txns[i].Group = groupID
	}
	request := userComponentGateRequest(t, sender, txns, []int{0})
	request.Requests = []signerapi.SignRequest{{
		AuthAddress: sender, TxnBytesHex: request.GroupBytesHex[0],
	}}
	plan, prepErr := prepareComponentSigning(request)
	if prepErr != nil {
		t.Fatal(prepErr)
	}

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	approval := prompt.approvalService(audit)
	approval.UserAutoApprove = userAutoApproveDefault(true)
	svc := newComponentGateService(audit, approval, &policy.Config{TransactionTypes: policytest.AllowAllTypes()}, sender)
	if rule, gateErr := svc.gateUserComponentSigning(t.Context(), plan); gateErr != nil || rule != "" {
		t.Fatalf("gateUserComponentSigning() = %q, %v; want no review rule for dummy suffix", rule, gateErr)
	}
	if prompt.calls != 0 {
		t.Fatalf("operator prompts = %d, want 0: frozen dummy suffix entered the policy gate", prompt.calls)
	}
}

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
			Type:        keytypes.GuardedFalcon1024Cosigner1024V1,
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
		HasClient:      func() bool { return true },
		KnownAddresses: func() map[string]bool { return nil },
		RequestSigningApproval: func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			p.calls++
			p.address = address
			p.description = description
			return p.approve, nil
		},
	}
}

// newComponentGateService builds a user-role component service under cfg,
// or under the compiled defaults when cfg is nil.
func newComponentGateService(audit *testAuditLogger, approval *ApprovalService, cfg *policy.Config, guardedAccount string) *Service {
	if cfg == nil {
		cfg = policy.DefaultConfig()
	}
	return &Service{
		Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
			return PlannerRuntimeSnapshot{
				KeyFiles: map[string]string{guardedAccount: "guarded.key"},
				KeyTypes: map[string]string{guardedAccount: keytypes.GuardedFalcon1024Cosigner1024V1},
			}
		}},
		Approval:                      approval,
		AuditLog:                      audit,
		IsUnlocked:                    func() bool { return true },
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		PolicyFor:                     fixedPolicy(cfg),
	}
}

// countOperationLease wires a counting BeforeExecute onto svc and returns the
// acquire/release counters.
func countOperationLease(svc *Service) (acquired, released *int) {
	acquired, released = new(int), new(int)
	svc.BeforeExecute = func() (func(), *ServiceError) {
		*acquired++
		return func() { *released++ }, nil
	}
	return acquired, released
}

func userComponentGateRequest(t *testing.T, sender string, txns []types.Transaction, targetIndices []int) componentPlanRequest {
	t.Helper()
	groupBytesHex := make([]string, len(txns))
	for i, txn := range txns {
		groupBytesHex[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	return componentPlanRequest{
		RequestID:     "cmp-gate-test",
		Role:          ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: groupBytesHex,
		TargetIndices: targetIndices,
	}
}

func TestSignComponentUserRoleRejectedBySignerPolicy(t *testing.T) {
	provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-policy-reject.v1")}
	coresigning.Register(provider)

	sender := types.Address{21}.String()
	receiver := types.Address{22}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), &policy.Config{TransactionTypes: policytest.AllowAllTypes(), MaxFeeMicroAlgos: 1}, sender)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	_, err := svc.signComponentWithContext(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), nil)
	if err == nil {
		t.Fatal("SignComponentWithContext() error = nil, want session required")
	}

	_, err = svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponent error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "policy engine rejected request") {
		t.Fatalf("SignComponent error = %q, want policy engine rejection", err.Message)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 for policy rejection", prompt.calls)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0: rejected requests must not decrypt key material", session.calls)
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
	provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-operator-approve.v1")}
	coresigning.Register(provider)

	sender := types.Address{23}.String()
	receiver := types.Address{24}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil, sender)
	leaseAcquired, leaseReleased := countOperationLease(svc)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	result, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err != nil {
		t.Fatalf("SignComponent error = %v", err)
	}
	if len(result.Signatures) != 2 {
		t.Fatalf("Signatures len = %d, want 2", len(result.Signatures))
	}
	if *leaseAcquired != 1 || *leaseReleased != 1 {
		t.Fatalf("operation lease acquired/released = %d/%d, want 1/1", *leaseAcquired, *leaseReleased)
	}
	if session.calls != 1 {
		t.Fatalf("session calls = %d, want single signing load", session.calls)
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
	provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-operator-deny.v1")}
	coresigning.Register(provider)

	sender := types.Address{25}.String()
	receiver := types.Address{26}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil, sender)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	_, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("SignComponent error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "rejected by operator") {
		t.Fatalf("SignComponent error = %q, want operator rejection", err.Message)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0: denied requests must not decrypt key material", session.calls)
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
	provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-user-auto.v1")}
	coresigning.Register(provider)

	sender := types.Address{27}.String()
	receiver := types.Address{28}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: false}
	approval := prompt.approvalService(audit)
	approval.UserAutoApprove = userAutoApproveDefault(true)
	svc := newComponentGateService(audit, approval, nil, sender)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

	result, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
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

func TestSignComponentUserRoleForeignRekeyReviewWithUserAutoApprove(t *testing.T) {
	for _, auto := range []bool{false, true} {
		name := "manual"
		if auto {
			name = "auto"
		}
		t.Run(name, func(t *testing.T) {
			provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-foreign-review.v1")}
			coresigning.Register(provider)

			sender := types.Address{29}.String()
			receiver := types.Address{30}.String()
			txns := []types.Transaction{
				testnetPaymentTransaction(t, sender, receiver, 1),
				testnetPaymentTransaction(t, receiver, receiver, 0),
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
			approval.UserAutoApprove = userAutoApproveDefault(auto)
			approval.HasClient = func() bool { return !auto }
			svc := newComponentGateService(audit, approval, &policy.Config{TransactionTypes: policytest.AllowAllTypes()}, sender)
			session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}

			result, svcErr := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0}), session)
			if svcErr != nil {
				t.Fatalf("SignComponent error = %v", svcErr)
			}
			if len(result.Signatures) != 1 {
				t.Fatalf("Signatures len = %d, want 1", len(result.Signatures))
			}
			wantPrompts := 1
			if auto {
				wantPrompts = 0
			}
			if prompt.calls != wantPrompts {
				t.Fatalf("prompt calls = %d, want %d", prompt.calls, wantPrompts)
			}
			if len(audit.approved) != 1 || audit.approved[0].policyRule != policy.AlwaysReviewWarningsRuleID {
				t.Fatalf("approved audit entries = %#v, want always-review rule ID", audit.approved)
			}

		})
	}
}

func TestSignComponentUserRoleWithoutAdminClientFailsClosed(t *testing.T) {
	sender := types.Address{32}.String()
	receiver := types.Address{33}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	approval := prompt.approvalService(audit)
	approval.HasClient = func() bool { return false }
	svc := newComponentGateService(audit, approval, nil, sender)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial("test.component-gate-no-client.v1")}

	_, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
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
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil, receiver)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial("test.component-gate-preflight.v1")}

	_, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("SignComponent error = %#v, want bad request", err)
	}
	if !strings.Contains(err.Message, "not found") {
		t.Fatalf("SignComponent error = %q, want key not found", err.Message)
	}
	if prompt.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 when preflight fails", prompt.calls)
	}
	if session.calls != 0 {
		t.Fatalf("session calls = %d, want 0: metadata preflight must not decrypt", session.calls)
	}
}

func componentGateContext() context.Context {
	return context.Background()
}

// The user-role component gate applies the signing key's transaction_types
// verdict: a rejected type never reaches the prompt or the key, and a
// reviewed type prompts.
func TestSignComponentUserRoleHonoursTransactionTypeVerdicts(t *testing.T) {
	provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-type-verdict.v1")}
	coresigning.Register(provider)

	sender := types.Address{41}.String()
	receiver := types.Address{42}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	// The grouped payments carry no genesis hash, so the configs keep the
	// compiled defaults' routing posture and change only the type verdicts.
	rejecting := policy.DefaultConfig()
	rejecting.TransactionTypes = policy.TransactionTypesV1{policy.TransactionTypeWildcard: policy.TransactionTypeAllow, "pay": policy.TransactionTypeReject}
	svc := newComponentGateService(audit, prompt.approvalService(audit), rejecting, sender)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}
	_, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, policy.TransactionTypeRuleID("pay")) {
		t.Fatalf("SignComponent(pay rejected) error = %#v, want the type rejection", err)
	}
	if prompt.calls != 0 || session.calls != 0 {
		t.Fatalf("prompt calls = %d session calls = %d, want none for a rejected type", prompt.calls, session.calls)
	}

	reviewing := policy.DefaultConfig()
	reviewing.TransactionTypes = policy.TransactionTypesV1{policy.TransactionTypeWildcard: policy.TransactionTypeAllow, "pay": policy.TransactionTypeReview}
	svc = newComponentGateService(audit, prompt.approvalService(audit), reviewing, sender)
	session = &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}
	result, err := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if err != nil || len(result.Signatures) != 2 {
		t.Fatalf("SignComponent(pay reviewed) = %+v, %v; want signatures after the prompt", result, err)
	}
	if prompt.calls != 1 {
		t.Fatalf("prompt calls = %d, want 1 for a reviewed type", prompt.calls)
	}
}

// Guarded user-component signing applies the same known-network gate as /sign
// planning: an unknown genesis hash is refused before policy, so it can never
// fall through to the operator default or user_auto_approve.
func TestSignComponentUserRoleRejectsUnknownNetworkBeforePolicy(t *testing.T) {
	provider := &componentUserTestProvider{family: uniqueSigningTestFamily("test.component-gate-unknown-network.v1")}
	coresigning.Register(provider)

	sender := types.Address{51}.String()
	receiver := types.Address{52}.String()
	txns := []types.Transaction{
		paymentTransaction(t, sender, receiver, 1),
		paymentTransaction(t, sender, receiver, 2),
	}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txns[0].Group, txns[1].Group = groupID, groupID

	audit := &testAuditLogger{}
	prompt := &componentGatePrompt{approve: true}
	svc := newComponentGateService(audit, prompt.approvalService(audit), nil, sender)
	session := &cloningComponentSession{address: sender, fresh: guardedGateKeyMaterial(provider.family)}
	_, signErr := svc.signComponentWithSession(componentGateContext(), userComponentGateRequest(t, sender, txns, []int{0, 1}), session)
	if signErr == nil || signErr.Kind != ErrorBadRequest || !strings.Contains(signErr.Message, "unrecognized genesis hash") {
		t.Fatalf("SignComponent error = %#v, want a bad request for the unknown network", signErr)
	}
	if prompt.calls != 0 || session.calls != 0 {
		t.Fatalf("prompt calls = %d session calls = %d, want none for an unknown network", prompt.calls, session.calls)
	}
}
