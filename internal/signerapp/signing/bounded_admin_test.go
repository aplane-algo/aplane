// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

func testBoundedAdminPlan(t *testing.T) (*PlanResult, signerapi.BoundedAdminRequest) {
	t.Helper()
	txn := testBoundedRekey()
	metadata := testBoundedMetadata(t, boundedmeta.AdminAuthorizationAdmin)
	spendingKey := make([]byte, boundedmeta.FalconAdminPublicKeySize)
	for i := range spendingKey {
		spendingKey[i] = 0x11
	}
	return &PlanResult{
			AllTxns:            []types.Transaction{txn},
			PassthroughIndices: map[int]bool{},
			ForeignIndices:     map[int]bool{},
			BoundedItems: []*boundedPlanItem{{
				Path:              boundedPathAdminKeyRekey,
				Metadata:          metadata,
				SpendingPublicKey: spendingKey,
			}},
		}, signerapi.BoundedAdminRequest{
			Operation: signerapi.BoundedAdminOperationRekey,
			Requests: []signerapi.SignRequest{{
				AuthAddress: txn.Sender.String(),
				TxnBytesHex: "00",
			}},
		}
}

func TestValidateBoundedAdminPlanRequiresNarrowTypedPath(t *testing.T) {
	plan, request := testBoundedAdminPlan(t)
	index, item, err := validateBoundedAdminPlan(request, plan)
	if err != nil || index != 0 || item != plan.BoundedItems[0] {
		t.Fatalf("validateBoundedAdminPlan() = (%d, %p, %v)", index, item, err)
	}

	tests := []struct {
		name   string
		mutate func(*PlanResult, *signerapi.BoundedAdminRequest)
	}{
		{name: "unknown operation", mutate: func(_ *PlanResult, request *signerapi.BoundedAdminRequest) { request.Operation = "close" }},
		{name: "caller args", mutate: func(_ *PlanResult, request *signerapi.BoundedAdminRequest) {
			request.Requests[0].LsigArgs = map[string]string{"admin": "00"}
		}},
		{name: "spending key path", mutate: func(plan *PlanResult, _ *signerapi.BoundedAdminRequest) {
			plan.BoundedItems[0].Path = boundedPathSpendingKeyRekey
		}},
		{name: "non Falcon base", mutate: func(plan *PlanResult, _ *signerapi.BoundedAdminRequest) {
			plan.BoundedItems[0].SpendingPublicKey = []byte{1}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutatedPlan, mutatedRequest := testBoundedAdminPlan(t)
			test.mutate(mutatedPlan, &mutatedRequest)
			if _, _, err := validateBoundedAdminPlan(mutatedRequest, mutatedPlan); err == nil {
				t.Fatal("validateBoundedAdminPlan() error = nil")
			}
		})
	}
}

func TestBuildBoundedAdminResultPublishesRecomputedTranscript(t *testing.T) {
	plan, request := testBoundedAdminPlan(t)
	result, err := buildBoundedAdminResult(plan, len(request.Requests), 0, plan.BoundedItems[0], []string{"partial"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != signerapi.BoundedAdminOperationRekey || result.Authorization.BaseSignatureArgCount != 1 || result.Authorization.AdminSignatureArgIndex != 1 {
		t.Fatalf("result = %#v", result)
	}
	if result.Authorization.SpendingPublicKeyHex != hex.EncodeToString(plan.BoundedItems[0].SpendingPublicKey) {
		t.Fatal("result omitted spending public key")
	}
	if result.Authorization.ContractAdminKeyID != plan.BoundedItems[0].Metadata.AdminKeyID {
		t.Fatal("result contract admin key ID mismatch")
	}
	txID := algocrypto.TransactionID(plan.AllTxns[0])
	if result.Authorization.TransactionID != algocrypto.TransactionIDString(plan.AllTxns[0]) || len(txID) != 32 || len(result.Authorization.MessageHex) != 64 {
		t.Fatalf("result transcript = %#v", result.Authorization)
	}
}

// TestBoundedAdminRequiredEmitsContractedCode pins the plain-/sign rejection of
// admin-key bounded operations to the contracted wire code, which clients route
// on to redirect the operation to POST /sign/bounded-admin.
func TestBoundedAdminRequiredEmitsContractedCode(t *testing.T) {
	err := boundedAdminRequired()
	if err.Code() != signerapi.ErrCodeBoundedAdminRequired {
		t.Fatalf("Code() = %q, want %q", err.Code(), signerapi.ErrCodeBoundedAdminRequired)
	}
	if err.HTTPStatus() != 400 {
		t.Fatalf("HTTPStatus() = %d, want 400", err.HTTPStatus())
	}
}
