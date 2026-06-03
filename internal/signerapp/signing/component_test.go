// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/txnutil"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestPrepareComponentSigningCanonicalizesTargetsAndMessages(t *testing.T) {
	sender := types.Address{1}.String()
	receiver := types.Address{2}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)

	req := signerapi.ComponentSignRequest{
		RequestID:     "cli-component-1",
		Role:          signerapi.ComponentSignRoleUser,
		ComponentKey:  sender,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{1, 0},
	}

	plan, err := PrepareComponentSigning(req)
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	if plan.RequestID != req.RequestID || plan.ComponentKey != sender {
		t.Fatalf("plan request metadata = %#v, want request_id %q component key %q", plan, req.RequestID, sender)
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

func TestPrepareComponentSigningUsesAttestorRoleDomain(t *testing.T) {
	sender := types.Address{3}.String()
	receiver := types.Address{4}.String()
	txn := paymentTransaction(t, sender, receiver, 7)

	req := signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		ComponentKey:  "attkey_example",
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}

	plan, err := PrepareComponentSigning(req)
	if err != nil {
		t.Fatalf("PrepareComponentSigning() error = %v", err)
	}
	if plan.MessageRole != message.RoleAttestor {
		t.Fatalf("MessageRole = %v, want attestor", plan.MessageRole)
	}
	userMsg := message.ComponentMessage(message.RoleUser, plan.Group.Entries[0].TxID)
	if bytes.Equal(plan.Targets[0].Message[:], userMsg[:]) {
		t.Fatal("attestor component message matched user-role message")
	}
}

func TestPrepareComponentSigningRejectsMalformedGroupBytes(t *testing.T) {
	_, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("PrepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "decode transaction") {
		t.Fatalf("PrepareComponentSigning() error = %q, want decode transaction", err.Message)
	}
}

func TestPrepareComponentSigningRejectsDivergentGroup(t *testing.T) {
	sender := types.Address{5}.String()
	receiver := types.Address{6}.String()
	txns := groupedPaymentTransactions(t, sender, receiver)
	txns[1].Group = types.Digest{9}

	_, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("PrepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "divergent group ID") {
		t.Fatalf("PrepareComponentSigning() error = %q, want divergent group ID", err.Message)
	}
}

func TestPrepareComponentSigningRejectsInvalidRequestShape(t *testing.T) {
	_, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleUser,
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("PrepareComponentSigning() error = %v, want bad request", err)
	}
	if !strings.Contains(err.Message, "component_key is required") {
		t.Fatalf("PrepareComponentSigning() error = %q, want missing component_key", err.Message)
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
