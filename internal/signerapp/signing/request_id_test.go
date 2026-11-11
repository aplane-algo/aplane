// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"regexp"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/keys"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

var mintedRequestID = regexp.MustCompile(`^req-[0-9a-f]{16}$`)

// A minted request ID is random, so requests sent without one in the same
// instant never share it, and it fits every bound on a request ID: the
// request validators, the audit operation_id, and the part of a waiting
// request's ID the signer console prints. A supplied ID is kept.
func TestRequestIDMintsAUniqueIDThatFitsItsBounds(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10_000; i++ {
		id := RequestID("")
		if !mintedRequestID.MatchString(id) {
			t.Fatalf("minted ID %q, want req- and 16 hex digits", id)
		}
		if requestIDPreview(id) != id {
			t.Fatalf("the console prints %q of the minted %q, want all of it", requestIDPreview(id), id)
		}
		if err := (signerapi.CancelSignRequest{RequestID: id}).Validate(); err != nil {
			t.Fatalf("minted ID %q is not a valid request_id: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("minted ID %q twice", id)
		}
		seen[id] = true
	}
	if got := RequestID("client-7"); got != "client-7" {
		t.Fatalf("RequestID(client-7) = %q, want the supplied ID", got)
	}
}

// approvingCoordinator is the real approval coordinator with an apadmin that
// approves every prompt, and the request IDs the prompts were held under.
func approvingCoordinator(t *testing.T) (*ApprovalService, *[]string) {
	t.Helper()
	var coordinator *signerapproval.Coordinator
	coordinator = signerapproval.New(func() bool { return true }, func(prompt *signerapproval.SignRequest) bool {
		go coordinator.HandleSignResponse(&signerapproval.SignResponse{ID: prompt.ID, Approved: true})
		return true
	}, nil)
	var requestIDs []string
	return &ApprovalService{
		HasClient:                     func() bool { return true },
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		KnownAddresses:                func() map[string]bool { return nil },
		ApprovalWait:                  func() time.Duration { return 10 * time.Second },
		RequestSigningApprovalResponseContext: func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
			requestIDs = append(requestIDs, requestID)
			return coordinator.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		},
	}, &requestIDs
}

// A direct caller of the approval service that supplies no request ID is
// prompted under a minted one, which the coordinator accepts.
func TestADirectApprovalWithNoRequestIDIsPromptedUnderAMintedOne(t *testing.T) {
	svc, requestIDs := approvingCoordinator(t)
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}}
	txns := []types.Transaction{txn}

	if err := svc.RequestSingleTxnApproval(signerapi.SignRequest{AuthAddress: "AUTH"}, txns, txns, 0, 0, 0); err != nil {
		t.Fatalf("RequestSingleTxnApproval() error = %v", err)
	}
	if err := svc.RequestSingleTxnApprovalWithContext(context.Background(), signerapi.SignRequest{AuthAddress: "AUTH"}, txns, txns, 0, 0, 0); err != nil {
		t.Fatalf("RequestSingleTxnApprovalWithContext() error = %v", err)
	}
	group := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTH"}}}
	plan := &PlanResult{ForeignIndices: map[int]bool{}}
	if err := svc.RequestGroupApproval(group, plan, "desc", 0, 0, txns); err != nil {
		t.Fatalf("RequestGroupApproval() error = %v", err)
	}
	if err := svc.RequestGroupApprovalWithContext(context.Background(), group, plan, "desc", 0, 0, txns); err != nil {
		t.Fatalf("RequestGroupApprovalWithContext() error = %v", err)
	}

	if len(*requestIDs) != 4 {
		t.Fatalf("%d prompts, want 4", len(*requestIDs))
	}
	seen := make(map[string]bool)
	for _, id := range *requestIDs {
		if !mintedRequestID.MatchString(id) || seen[id] {
			t.Fatalf("prompts held under %q, want a distinct minted ID each", *requestIDs)
		}
		seen[id] = true
	}
}

// A direct caller of /sign/component's service that supplies no request ID
// gets a response with a minted one, which the client accepts.
func TestADirectComponentCallWithNoRequestIDReturnsAMintedOne(t *testing.T) {
	publicKey, privateKey := testFalconComponentKeypair(t, 0x63)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	source, dest := types.Address{33}.String(), types.Address{34}.String()
	txn := testnetPaymentTransaction(t, source, dest, 1)
	store := &componentKeyStore{key: &coresigning.KeyMaterial{
		Type:     witness.Falcon1024V1,
		Category: keys.CategoryWitness,
		Value: &coresigning.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    append([]byte(nil), publicKey...),
			PrivateKey:   append([]byte(nil), privateKey...),
		},
	}}
	svc := &Service{
		Planner:          &Planner{Snapshot: func() PlannerRuntimeSnapshot { return PlannerRuntimeSnapshot{} }},
		PolicyFor:        fixedPolicy(cosignerRoutePolicy(t, source, dest)),
		HoldsCosignerKey: holdsAllCosignerKeys,
	}

	resp, signErr := svc.SignComponentsWithContext(context.Background(), signerapi.ComponentRequest{
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindCosigner, ComponentKey: componentKey}},
	}, newComponentKeySession(store))
	if signErr != nil {
		t.Fatalf("SignComponentsWithContext() error = %v", signErr)
	}
	if !mintedRequestID.MatchString(resp.RequestID) {
		t.Fatalf("response request_id = %q, want a minted ID", resp.RequestID)
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("the client would refuse the response: %v", err)
	}
}

// A direct caller of /sign/assemble's service that supplies no request ID
// gets a response with a minted one, which the client accepts.
func TestADirectAssemblyWithNoRequestIDReturnsAMintedOne(t *testing.T) {
	txn := paymentTransaction(t, types.Address{35}.String(), types.Address{36}.String(), 7)
	groupBytesHex := []string{txnutil.EncodeWithPrefixHex(txn)}
	if _, err := canonical.DecodeGroupHex(groupBytesHex); err != nil {
		t.Fatal(err)
	}
	passthrough := msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{0x01}})

	result, signErr := (&Service{}).AssembleWithContext(context.Background(), signerapi.AssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Passthrough:   []signerapi.AssemblyPassthroughItem{{TargetIndex: 0, SignedTxnHex: hex.EncodeToString(passthrough)}},
	}, newComponentKeySession(&componentKeyStore{}))
	if signErr != nil {
		t.Fatalf("AssembleWithContext() error = %v", signErr)
	}
	if !mintedRequestID.MatchString(result.RequestID) {
		t.Fatalf("result request_id = %q, want a minted ID", result.RequestID)
	}
	resp := signerapi.AssemblyResponse{RequestID: result.RequestID, SignedGroup: result.SignedGroup}
	if err := resp.Validate(); err != nil {
		t.Fatalf("the client would refuse the response: %v", err)
	}
}
