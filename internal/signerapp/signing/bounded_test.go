// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func testBoundedMetadata(t *testing.T, authorization string) *boundedmeta.Metadata {
	t.Helper()
	metadata := &boundedmeta.Metadata{
		Contract:                boundedmeta.ContractV1,
		BaseSignatureArgLayout:  boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{1280}},
		ArgumentLayout:          boundedmeta.BaseArgumentLayout(boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}, authorization == boundedmeta.AdminAuthorizationAdmin),
		SpendEffects:            []string{"pay", "axfer"},
		MaxFee:                  5_000,
		Layer3Policy:            boundedmeta.Layer3PolicyCustom,
		PostSigningLogicSigSize: 2_000,
	}
	if authorization != "" {
		metadata.AdminOperations = []boundedmeta.AdminOperation{{
			Kind:          boundedmeta.AdminOperationRekey,
			Authorization: authorization,
			PolicyGate:    boundedmeta.PolicyGateNone,
		}}
	}
	if authorization == boundedmeta.AdminAuthorizationAdmin {
		publicKey := make([]byte, boundedmeta.FalconAdminPublicKeySize)
		for i := range publicKey {
			publicKey[i] = byte(i + 1)
		}
		keyID, err := boundedmeta.AdminKeyID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		metadata.AdminPublicKeyHex = hex.EncodeToString(publicKey)
		metadata.AdminKeyID = keyID
		metadata.ProgramBindingHex = strings.Repeat("01", boundedmeta.ProgramBindingSize)
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("test metadata invalid: %v", err)
	}
	return metadata
}

func testBoundedPayment() types.Transaction {
	sender := types.Address{1}
	return types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{2}, Amount: 1},
	}
}

func testBoundedRekey() types.Transaction {
	txn := testBoundedPayment()
	txn.Receiver = txn.Sender
	txn.Amount = 0
	txn.RekeyTo = types.Address{9}
	return txn
}

func testBoundedAssetOptIn() types.Transaction {
	sender := types.Address{1}
	return types.Transaction{
		Type:                   types.AssetTransferTx,
		Header:                 types.Header{Sender: sender, Fee: 1_000},
		AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 7, AssetReceiver: sender},
	}
}

func TestClassifyBoundedPath(t *testing.T) {
	spendingRekey := testBoundedMetadata(t, boundedmeta.AdminAuthorizationSpend)
	adminRekey := testBoundedMetadata(t, boundedmeta.AdminAuthorizationAdmin)
	noRekey := testBoundedMetadata(t, "")
	assetOptIn := testBoundedMetadata(t, "")
	assetOptIn.SpendEffects = []string{boundedmeta.SpendEffectAssetOptIn}
	assetTransferOnly := testBoundedMetadata(t, "")
	assetTransferOnly.SpendEffects = []string{boundedmeta.SpendEffectAxfer}

	tests := []struct {
		name     string
		txn      types.Transaction
		metadata *boundedmeta.Metadata
		wantPath boundedPath
		wantErr  string
	}{
		{name: "pure payment", txn: testBoundedPayment(), metadata: spendingRekey, wantPath: boundedPathPureSpend},
		{name: "asset opt-in", txn: testBoundedAssetOptIn(), metadata: assetOptIn, wantPath: boundedPathPureSpend},
		{name: "asset opt-in denied by transfer-only profile", txn: testBoundedAssetOptIn(), metadata: assetTransferOnly, wantErr: "does not allow spend effect \"asset_opt_in\""},
		{name: "spending key rekey", txn: testBoundedRekey(), metadata: spendingRekey, wantPath: boundedPathSpendingKeyRekey},
		{name: "admin key rekey", txn: testBoundedRekey(), metadata: adminRekey, wantPath: boundedPathAdminKeyRekey},
		{name: "rekey disabled", txn: testBoundedRekey(), metadata: noRekey, wantErr: "permanently disables rekey"},
		{name: "fee over profile", txn: func() types.Transaction { txn := testBoundedPayment(); txn.Fee = 5_001; return txn }(), metadata: spendingRekey, wantErr: "fee 5001 exceeds"},
		{name: "hybrid rekey transfer", txn: func() types.Transaction { txn := testBoundedRekey(); txn.Amount = 1; return txn }(), metadata: spendingRekey, wantErr: "hybrid transaction effects: rekey"},
		{name: "close effect", txn: func() types.Transaction {
			txn := testBoundedPayment()
			txn.CloseRemainderTo = types.Address{8}
			return txn
		}(), metadata: spendingRekey, wantErr: "transaction effects: close"},
		{name: "denied type", txn: types.Transaction{Type: types.ApplicationCallTx, Header: types.Header{Fee: 1_000}}, metadata: spendingRekey, wantErr: "transaction type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyBoundedPath(tt.txn, tt.metadata)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Message, tt.wantErr) {
					t.Fatalf("classifyBoundedPath() error = %#v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.wantPath {
				t.Fatalf("classifyBoundedPath() = (%q, %v), want (%q, nil)", got, err, tt.wantPath)
			}
		})
	}
}

func TestRunApprovalGatesForcedBoundedReviewPrecedesAutoApproval(t *testing.T) {
	autoApproveCalls := 0
	promptCalls := 0
	forcedRule := ""
	svc := &Service{}

	ruleID, err := svc.runApprovalGates(context.Background(), gateInput{
		AllTxns:            []types.Transaction{testBoundedRekey()},
		EvalCount:          1,
		ForcedReviewRuleID: policy.BoundedAdminOperationRequiresReviewRuleID,
		AutoApprove: func() (string, bool) {
			autoApproveCalls++
			return policy.AutoApproveSelfNoOpTransferRuleID, true
		},
		RequestOperatorApproval: func(_ context.Context, ruleID string) *ServiceError {
			promptCalls++
			forcedRule = ruleID
			return nil
		},
	}, nil)
	if err != nil {
		t.Fatalf("runApprovalGates() error = %v", err)
	}
	if autoApproveCalls != 0 || promptCalls != 1 {
		t.Fatalf("autoapprove/prompt calls = %d/%d, want 0/1", autoApproveCalls, promptCalls)
	}
	if ruleID != policy.BoundedAdminOperationRequiresReviewRuleID || forcedRule != ruleID {
		t.Fatalf("rule IDs = returned %q prompted %q", ruleID, forcedRule)
	}
}

func TestBuildApprovalDescriptionNamesBoundedRekeyAuthority(t *testing.T) {
	metadata := testBoundedMetadata(t, boundedmeta.AdminAuthorizationAdmin)
	txn := testBoundedRekey()
	description, _, _ := BuildApprovalDescription(
		signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: txn.Sender.String()}}},
		&PlanResult{
			AllTxns:            []types.Transaction{txn},
			PassthroughIndices: map[int]bool{},
			ForeignIndices:     map[int]bool{},
			BoundedItems: []*boundedPlanItem{{
				Path:     boundedPathAdminKeyRekey,
				Metadata: metadata,
			}},
		},
		[]types.Transaction{txn},
		func(types.Transaction) string { return "transaction" },
	)
	for _, want := range []string{
		"Bounded authorization contract admin operation: REKEY",
		"Authorization: external contract admin key " + metadata.AdminKeyID,
		"Profile maximum fee: 5000 microAlgos",
	} {
		if !strings.Contains(description, want) {
			t.Fatalf("approval description = %q, want containing %q", description, want)
		}
	}
}
