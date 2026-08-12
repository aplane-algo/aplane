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

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
)

func TestDescribeTxnForApprovalAddsAppCallMetadata(t *testing.T) {
	selector, err := appspec.SignatureSelector("increment(uint64)void")
	if err != nil {
		t.Fatalf("SignatureSelector() error = %v", err)
	}

	desc := describeTxnForApproval(
		types.Transaction{
			Type: types.ApplicationCallTx,
			ApplicationFields: types.ApplicationFields{
				ApplicationCallTxnFields: types.ApplicationCallTxnFields{
					ApplicationID: 123,
					OnCompletion:  types.NoOpOC,
					ApplicationArgs: [][]byte{
						append([]byte(nil), selector...),
					},
				},
			},
		},
		signerapi.SignRequest{
			AppCallInfo: &signerapi.AppCallInfo{
				Mode:   "abi",
				Method: "increment(uint64)void",
			},
		},
		func(txn types.Transaction) string {
			return "App Call: #123 (NoOp)\n  From: SOMEADDR"
		},
	)

	for _, want := range []string{
		"App Call [ABI]: #123 (NoOp)",
		"Mode: ABI",
		"Method: increment(uint64)void",
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q:\n%s", want, desc)
		}
	}
}

func TestDescribeTxnForApprovalIgnoresMismatchedAppCallMetadata(t *testing.T) {
	desc := describeTxnForApproval(
		types.Transaction{
			Type: types.ApplicationCallTx,
			ApplicationFields: types.ApplicationFields{
				ApplicationCallTxnFields: types.ApplicationCallTxnFields{
					ApplicationID: 123,
					OnCompletion:  types.NoOpOC,
					ApplicationArgs: [][]byte{
						bytes.Repeat([]byte{0xff}, 4),
					},
				},
			},
		},
		signerapi.SignRequest{
			AppCallInfo: &signerapi.AppCallInfo{
				Mode:   "abi",
				Method: "increment(uint64)void",
			},
		},
		func(txn types.Transaction) string {
			return "App Call: #123 (NoOp)\n  From: SOMEADDR"
		},
	)

	for _, unwanted := range []string{
		"App Call [ABI]:",
		"Mode: ABI",
		"Method: increment(uint64)void",
	} {
		if strings.Contains(desc, unwanted) {
			t.Fatalf("description unexpectedly contains %q:\n%s", unwanted, desc)
		}
	}
}

func TestDescribeTxnForApprovalMarksRawAppCalls(t *testing.T) {
	desc := describeTxnForApproval(
		types.Transaction{
			Type: types.ApplicationCallTx,
			ApplicationFields: types.ApplicationFields{
				ApplicationCallTxnFields: types.ApplicationCallTxnFields{
					ApplicationID: 123,
					OnCompletion:  types.NoOpOC,
				},
			},
		},
		signerapi.SignRequest{
			AppCallInfo: &signerapi.AppCallInfo{
				Mode: "raw",
			},
		},
		func(txn types.Transaction) string {
			return "App Call: #123 (NoOp)\n  From: SOMEADDR"
		},
	)

	if !strings.Contains(desc, "Mode: Raw") {
		t.Fatalf("description missing raw mode marker:\n%s", desc)
	}
	if strings.Contains(desc, "App Call [ABI]:") {
		t.Fatalf("raw app call unexpectedly labeled as ABI:\n%s", desc)
	}
}

func TestReviewabilityReason(t *testing.T) {
	tests := []struct {
		name string
		txn  types.Transaction
		want string
	}{
		{
			name: "payment reviewable",
			txn:  types.Transaction{Type: types.PaymentTx},
			want: "",
		},
		{
			name: "app create without programs blocked",
			txn: types.Transaction{
				Type: types.ApplicationCallTx,
				ApplicationFields: types.ApplicationFields{
					ApplicationCallTxnFields: types.ApplicationCallTxnFields{},
				},
			},
			want: "app create/update is not reviewable without both approval and clear program bytes",
		},
		{
			name: "app update without programs blocked",
			txn: types.Transaction{
				Type: types.ApplicationCallTx,
				ApplicationFields: types.ApplicationFields{
					ApplicationCallTxnFields: types.ApplicationCallTxnFields{
						ApplicationID: 7,
						OnCompletion:  types.UpdateApplicationOC,
					},
				},
			},
			want: "app create/update is not reviewable without both approval and clear program bytes",
		},
		{
			name: "app update with programs reviewable",
			txn: types.Transaction{
				Type: types.ApplicationCallTx,
				ApplicationFields: types.ApplicationFields{
					ApplicationCallTxnFields: types.ApplicationCallTxnFields{
						ApplicationID:     7,
						OnCompletion:      types.UpdateApplicationOC,
						ApprovalProgram:   []byte{0x01},
						ClearStateProgram: []byte{0x02},
						ExtraProgramPages: 1,
						GlobalStateSchema: types.StateSchema{NumUint: 1},
						LocalStateSchema:  types.StateSchema{NumByteSlice: 1},
					},
				},
			},
			want: "",
		},
		{
			name: "unknown type blocked",
			txn:  types.Transaction{Type: types.TxType("mystery")},
			want: "transaction type mystery is not reviewable in the current approval UI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reviewabilityReason(tt.txn); got != tt.want {
				t.Fatalf("reviewabilityReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApprovalWindowUsesGroupIntersection(t *testing.T) {
	firstValid, lastValid := approvalWindow([]types.Transaction{
		{Header: types.Header{FirstValid: 100, LastValid: 200}},
		{Header: types.Header{FirstValid: 120, LastValid: 180}},
		{Header: types.Header{FirstValid: 110, LastValid: 190}},
	})

	if firstValid != 120 || lastValid != 180 {
		t.Fatalf("approvalWindow() = (%d, %d), want (120, 180)", firstValid, lastValid)
	}
}

func TestGroupApprovalAddress(t *testing.T) {
	tests := []struct {
		name string
		req  signerapi.GroupSignRequest
		want string
	}{
		{
			name: "none",
			req:  signerapi.GroupSignRequest{},
			want: "",
		},
		{
			name: "single",
			req: signerapi.GroupSignRequest{
				Requests: []signerapi.SignRequest{
					{AuthAddress: "AUTH1"},
					{AuthAddress: "AUTH1"},
				},
			},
			want: "AUTH1",
		},
		{
			name: "multiple",
			req: signerapi.GroupSignRequest{
				Requests: []signerapi.SignRequest{
					{AuthAddress: "AUTH1"},
					{AuthAddress: "AUTH2"},
				},
			},
			want: "2 auth addresses (see details)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupApprovalAddress(tt.req); got != tt.want {
				t.Fatalf("groupApprovalAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildApprovalDescriptionTreatsSingleRequestedTxnWithDummiesAsSingle(t *testing.T) {
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "AUTHADDR",
			TxnBytesHex: "deadbeef",
		}},
	}
	plan := &PlanResult{
		DummiesNeeded:         1,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}
	allTxns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, FirstValid: 100, LastValid: 200}},
		{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}, FirstValid: 100, LastValid: 200}},
	}

	desc, firstValid, lastValid := BuildApprovalDescription(req, plan, allTxns, func(txn types.Transaction) string {
		return "txn"
	})

	if !strings.HasPrefix(desc, "=== SINGLE TRANSACTION ===\n\n") {
		t.Fatalf("description = %q, want single transaction header", desc)
	}
	if strings.Contains(desc, "TRANSACTION GROUP") {
		t.Fatalf("description = %q, did not expect group header", desc)
	}
	if firstValid != 100 || lastValid != 200 {
		t.Fatalf("approval window = (%d, %d), want (100, 200)", firstValid, lastValid)
	}
}

func TestBuildApprovalDescriptionOmitsDummyEntriesFromGroupApproval(t *testing.T) {
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{AuthAddress: "AUTH1", TxnBytesHex: "deadbeef"},
			{AuthAddress: "AUTH2", TxnBytesHex: "cafebabe"},
		},
	}
	plan := &PlanResult{
		DummiesNeeded:         1,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}
	allTxns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, FirstValid: 100, LastValid: 220}},
		{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}, FirstValid: 140, LastValid: 300}},
		{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{3}, FirstValid: 140, LastValid: 300}},
	}

	desc, firstValid, lastValid := BuildApprovalDescription(req, plan, allTxns, func(txn types.Transaction) string {
		return "txn"
	})

	if !strings.HasPrefix(desc, "=== TRANSACTION GROUP (2 transactions) ===\n") {
		t.Fatalf("description = %q, want requested transaction count in group header", desc)
	}
	if strings.Contains(desc, "[DUMMY - budget padding]") {
		t.Fatalf("description = %q, did not expect dummy approval entries", desc)
	}
	if strings.Contains(desc, "--- Transaction 3 of 2") {
		t.Fatalf("description = %q, did not expect appended dummy slot numbering", desc)
	}
	if firstValid != 140 || lastValid != 220 {
		t.Fatalf("approval window = (%d, %d), want (140, 220)", firstValid, lastValid)
	}
}

func TestBuildApprovalDescriptionDistinguishesCoveredAuthorizationFeeRequirement(t *testing.T) {
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTH"}}}
	plan := &PlanResult{
		FeeInfo:              DummyFeeInfo{ProgramFeeContribution: 300},
		LogicSigResourcePlan: lsigresource.Plan{ChargedProgramBytes: 3},
		PassthroughIndices:   map[int]bool{},
		ForeignIndices:       map[int]bool{},
	}
	txns := []types.Transaction{{Type: types.PaymentTx}}
	description, _, _ := BuildApprovalDescription(req, plan, txns, func(types.Transaction) string { return "txn" })
	if strings.Contains(description, "[MODIFIED BY SERVER]") {
		t.Fatalf("description incorrectly reports a fee mutation:\n%s", description)
	}
	if !strings.Contains(description, "[FEE REQUIREMENT COVERED BY EXISTING FEES]") ||
		!strings.Contains(description, "Required LogicSig program contribution: 300 microAlgos") {
		t.Fatalf("description does not explain the covered fee requirement:\n%s", description)
	}
}

func TestBuildApprovalDescriptionUsesOneBasedFeeTransactionNumbers(t *testing.T) {
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{}, {}, {}}}
	plan := &PlanResult{
		FeeInfo:            DummyFeeInfo{TotalFees: 2_000, FeeIndices: []int{0, 2}},
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
	}
	txns := []types.Transaction{{Type: types.PaymentTx}, {Type: types.PaymentTx}, {Type: types.PaymentTx}}
	description, _, _ := BuildApprovalDescription(req, plan, txns, func(types.Transaction) string { return "txn" })
	if !strings.Contains(description, "across transaction(s) [1 3]") {
		t.Fatalf("description does not use one-based transaction numbers:\n%s", description)
	}
}

func TestRequestSingleTxnApprovalBlocksNonReviewableTxn(t *testing.T) {
	called := false
	svc := &ApprovalService{
		HasClient: func(identityID string) bool { return true },
		RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			called = true
			return true, nil
		},
	}

	err := svc.RequestSingleTxnApproval(
		"default",
		signerapi.SignRequest{AuthAddress: "AUTH"},
		[]types.Transaction{{Type: types.TxType("mystery")}},
		[]types.Transaction{{Type: types.TxType("mystery")}},
		0,
		0,
		0,
	)
	if err == nil {
		t.Fatal("RequestSingleTxnApproval() error = nil, want blocked non-reviewable txn")
		return
	}
	if !strings.Contains(err.Message, "not reviewable") {
		t.Fatalf("unexpected error message: %q", err.Message)
	}
	if called {
		t.Fatal("RequestSigningApproval was called for non-reviewable transaction")
	}
}

func TestRequestGroupApprovalBlocksNonReviewableTxn(t *testing.T) {
	called := false
	svc := &ApprovalService{
		HasClient: func(identityID string) bool { return true },
		RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			called = true
			return true, nil
		},
		KnownAddresses: func(identityID string) map[string]bool { return nil },
	}

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{AuthAddress: "AUTH"},
		},
	}
	plan := &PlanResult{
		ForeignIndices: make(map[int]bool),
	}
	txns := []types.Transaction{{Type: types.TxType("mystery")}}

	err := svc.RequestGroupApproval("default", req, plan, "desc", 0, 0, txns)
	if err == nil {
		t.Fatal("RequestGroupApproval() error = nil, want blocked non-reviewable group")
		return
	}
	if !strings.Contains(err.Message, "not reviewable") {
		t.Fatalf("unexpected error message: %q", err.Message)
	}
	if called {
		t.Fatal("RequestSigningApproval was called for non-reviewable group")
	}
}

func TestRequestSingleTxnApprovalPassesWarningViolationsAndCanApprove(t *testing.T) {
	var gotViolations []signerapproval.Violation
	svc := &ApprovalService{
		HasClient:                     func(identityID string) bool { return true },
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		KnownAddresses:                func(identityID string) map[string]bool { return nil },
		EncodeTxnToHex: func(txn types.Transaction) string {
			return hex.EncodeToString(msgpack.Encode(txn))
		},
		RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			gotViolations = violations
			return true, nil
		},
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    types.MicroAlgos(approvalpolicy.DefaultMaxFeeMicroAlgos + 1),
		},
	}

	err := svc.RequestSingleTxnApproval(
		"default",
		signerapi.SignRequest{AuthAddress: "AUTH"},
		[]types.Transaction{txn},
		[]types.Transaction{txn},
		0,
		0,
		0,
	)
	if err != nil {
		t.Fatalf("RequestSingleTxnApproval() error = %v, want nil", err)
	}
	if len(gotViolations) != 1 {
		t.Fatalf("len(violations) = %d, want 1", len(gotViolations))
	}
	if gotViolations[0].Field != "Fee" || gotViolations[0].Severity != "warning" {
		t.Fatalf("violations[0] = %#v, want fee warning", gotViolations[0])
	}
}

func TestRequestSingleTxnApprovalUsesConfiguredWaitAndAuditsTimeout(t *testing.T) {
	audit := &testAuditLogger{}
	var gotTimeout time.Duration
	svc := &ApprovalService{
		ApprovalWait:                  func() time.Duration { return 45 * time.Second },
		AuditLog:                      audit,
		HasClient:                     func(identityID string) bool { return true },
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		KnownAddresses:                func(identityID string) map[string]bool { return nil },
		EncodeTxnToHex:                func(txn types.Transaction) string { return hex.EncodeToString(msgpack.Encode(txn)) },
		RequestSigningApprovalResponse: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
			gotTimeout = timeout
			return signerapproval.SignResponse{}, signerapproval.ErrApprovalTimeout
		},
	}

	txn := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: types.Address{1}},
	}

	err := svc.RequestSingleTxnApproval(
		"default",
		signerapi.SignRequest{AuthAddress: "AUTH"},
		[]types.Transaction{txn},
		[]types.Transaction{txn},
		0,
		0,
		0,
	)
	if err == nil {
		t.Fatal("RequestSingleTxnApproval() error = nil, want timeout")
	}
	if gotTimeout != 45*time.Second {
		t.Fatalf("approval timeout = %s, want 45s", gotTimeout)
	}
	if len(audit.rejected) != 1 {
		t.Fatalf("len(audit.rejected) = %d, want 1", len(audit.rejected))
	}
	if audit.rejected[0].reason != "txn_approval_timeout" {
		t.Fatalf("audit reason = %q, want txn_approval_timeout", audit.rejected[0].reason)
	}
}

func TestRequestSingleTxnApprovalAuditsForcedReviewRuleOnReject(t *testing.T) {
	audit := &testAuditLogger{}
	svc := &ApprovalService{
		AuditLog:                      audit,
		HasClient:                     func(identityID string) bool { return true },
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		KnownAddresses:                func(identityID string) map[string]bool { return nil },
		EncodeTxnToHex:                func(txn types.Transaction) string { return hex.EncodeToString(msgpack.Encode(txn)) },
		RequestSigningApprovalResponse: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
			return signerapproval.SignResponse{ID: requestID, Approved: false}, nil
		},
	}

	txn := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: types.Address{1}},
	}
	err := svc.requestSingleTxnApprovalWithContext(
		context.Background(),
		"default",
		"",
		signerapi.SignRequest{AuthAddress: "AUTH"},
		[]types.Transaction{txn},
		[]types.Transaction{txn},
		0,
		0,
		0,
		policy.ReviewAlgoPaymentExceededRuleID,
	)
	if err == nil {
		t.Fatal("requestSingleTxnApprovalWithContext() error = nil, want operator rejection")
	}
	if len(audit.rejected) != 1 {
		t.Fatalf("len(audit.rejected) = %d, want 1", len(audit.rejected))
	}
	if got := audit.rejected[0].policyRule; got != policy.ReviewAlgoPaymentExceededRuleID {
		t.Fatalf("policyRule = %q, want %q", got, policy.ReviewAlgoPaymentExceededRuleID)
	}
}

func TestRequestGroupApprovalPassesWarningViolationsAndCanApprove(t *testing.T) {
	var gotViolations []signerapproval.Violation
	var gotRequestID string
	svc := &ApprovalService{
		HasClient:      func(identityID string) bool { return true },
		KnownAddresses: func(identityID string) map[string]bool { return nil },
		RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			gotRequestID = requestID
			gotViolations = violations
			return true, nil
		},
	}

	req := signerapi.GroupSignRequest{
		RequestID: "cli-group-1",
		Requests: []signerapi.SignRequest{
			{AuthAddress: "AUTH1"},
			{AuthAddress: "AUTH2"},
		},
	}
	plan := &PlanResult{
		ForeignIndices: make(map[int]bool),
	}
	txns := []types.Transaction{
		{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: types.Address{1}},
			PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: types.Address{9}},
		},
		{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender: types.Address{2},
			},
		},
	}

	err := svc.RequestGroupApproval("default", req, plan, "desc", 0, 0, txns)
	if err != nil {
		t.Fatalf("RequestGroupApproval() error = %v, want nil", err)
	}
	if len(gotViolations) != 1 {
		t.Fatalf("len(violations) = %d, want 1", len(gotViolations))
	}
	if gotRequestID != "cli-group-1" {
		t.Fatalf("approval request ID = %q, want cli-group-1", gotRequestID)
	}
	if gotViolations[0].Field != "Tx 1/2: CloseRemainderTo" || gotViolations[0].Severity != "critical" {
		t.Fatalf("violations[0] = %#v, want prefixed close remainder warning", gotViolations[0])
	}
}

func TestRequestSingleTxnApprovalUsesSuppliedRequestID(t *testing.T) {
	var gotRequestID string
	svc := &ApprovalService{
		HasClient:                     func(identityID string) bool { return true },
		GenerateTxnDescriptionFromTxn: func(txn types.Transaction) string { return "txn" },
		KnownAddresses:                func(identityID string) map[string]bool { return nil },
		EncodeTxnToHex:                func(txn types.Transaction) string { return hex.EncodeToString(msgpack.Encode(txn)) },
		RequestSigningApproval: func(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			gotRequestID = requestID
			return true, nil
		},
	}

	txn := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: types.Address{1}},
	}

	err := svc.requestSingleTxnApprovalWithContext(
		context.Background(),
		"default",
		"cli-single-1",
		signerapi.SignRequest{AuthAddress: "AUTH"},
		[]types.Transaction{txn},
		[]types.Transaction{txn},
		0,
		0,
		0,
		"",
	)
	if err != nil {
		t.Fatalf("requestSingleTxnApprovalWithContext() error = %v, want nil", err)
	}
	if gotRequestID != "cli-single-1" {
		t.Fatalf("approval request ID = %q, want cli-single-1", gotRequestID)
	}
}
