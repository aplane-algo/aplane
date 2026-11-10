// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// heldTestSnapshot holds a bounded account with listTestTarget on its rekey-to
// list, under its own address, and a native key.
func heldTestSnapshot(t *testing.T, account, native types.Address) PlannerRuntimeSnapshot {
	t.Helper()
	metadata, params := listTestAccount(t)
	return PlannerRuntimeSnapshot{
		KeyFiles: map[string]string{account.String(): "account.key", native.String(): "native.key"},
		KeyMetadata: map[string]PlannerKeyMetadata{
			account.String(): {PublicKeyHex: "01", BaseKeyType: "aplane.falcon1024.v1", Parameters: params, BoundedAuthorization: metadata},
		},
	}
}

// A foreign position is recognised as this signer's from the signer's records:
// by its sender, or by the key its request names. An address the signer doesn't
// hold stays foreign whatever the request says, and a position the request signs
// is never one.
func TestHeldForeignPositionsComeFromTheSignersRecords(t *testing.T) {
	account, native, stranger := listTestRekey(listTestTarget).Sender, types.Address{0x71}, types.Address{0x72}
	snapshot := heldTestSnapshot(t, account, native)
	from := func(sender types.Address) types.Transaction {
		txn := listTestRekey(listTestTarget)
		txn.Sender = sender
		return txn
	}
	txns := []types.Transaction{from(account), from(native), from(stranger), from(account), from(stranger), from(stranger)}
	foreign := map[int]bool{0: true, 1: true, 2: true, 4: true, 5: true}
	holders := map[int]string{4: account.String(), 5: types.Address{0x73}.String()}
	held := heldForeignPositions(snapshot, txns, foreign, holders)

	if held[0] == nil || !held[0].ListedRekeyTargets[listTestTarget.String()] {
		t.Errorf("a held account with a list: %+v", held[0])
	}
	if held[1] == nil || held[1].ListedRekeyTargets != nil {
		t.Errorf("a held native key has no list: %+v", held[1])
	}
	if held[2] != nil {
		t.Errorf("an address the signer doesn't hold was recognised: %+v", held[2])
	}
	if held[3] != nil {
		t.Errorf("a position the request signs was recognised as one it doesn't: %+v", held[3])
	}
	if held[0] != nil && held[0].NamedAuthorizer != "" || held[1] != nil && held[1].NamedAuthorizer != "" {
		t.Errorf("a position recognised by its sender carries a named authorizer: %+v, %+v", held[0], held[1])
	}
	// The request names a held account for another sender. That is the request's
	// word: it is recorded as such, and gives the warnings no list.
	if held[4] == nil || held[4].NamedAuthorizer != account.String() || held[4].ListedRekeyTargets != nil {
		t.Errorf("a position whose named key is held: %+v", held[4])
	}
	if heldByRecords(held) != 2 {
		t.Errorf("heldByRecords = %d, want the two recognised by sender", heldByRecords(held))
	}
	if held[5] != nil {
		t.Errorf("a named key the signer doesn't hold was recognised: %+v", held[5])
	}
	if len(held) != 3 {
		t.Errorf("held = %v, want positions 0, 1 and 4", held)
	}
	if got := heldForeignPositions(snapshot, txns, nil, nil); got != nil {
		t.Errorf("a request with no foreign position: %v", got)
	}
	if got := heldForeignPositions(PlannerRuntimeSnapshot{}, txns, foreign, holders); got != nil {
		t.Errorf("a signer with no keys: %v", got)
	}
}

// The second request of a mixed cosigned group carries the cosigned account's
// listed rekey as a position it doesn't sign. The review calls it this signer's
// account and names the listed handover, as the request that signed it did. It
// used to say FOREIGN and warn that control is lost (max review #10, audit U4).
// A position the signer doesn't hold is still foreign, with that warning.
func TestGroupReviewNamesAHeldPositionAndItsListedHandover(t *testing.T) {
	account, native, stranger := listTestRekey(listTestTarget).Sender, types.Address{0x71}, types.Address{0x72}
	snapshot := heldTestSnapshot(t, account, native)
	payment := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: native, Fee: 1_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
	}
	review := func(t *testing.T, rekeySender types.Address) (string, []signerapproval.Violation) {
		t.Helper()
		rekey := listTestRekey(listTestTarget)
		rekey.Sender, rekey.Receiver = rekeySender, rekeySender
		txns := []types.Transaction{rekey, payment}
		foreign := map[int]bool{0: true}
		plan := &PlanResult{
			AllTxns: txns, ForeignIndices: foreign, HasForeign: true,
			PassthroughIndices: map[int]bool{}, BoundedItems: make([]*boundedPlanItem, 2),
			HeldForeign: heldForeignPositions(snapshot, txns, foreign, nil),
		}
		req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{TxnBytesHex: "00"}, {AuthAddress: native.String()}}}
		description, _, _ := BuildApprovalDescription(req, plan, txns, func(types.Transaction) string { return "txn\n" })
		var got []signerapproval.Violation
		svc := &ApprovalService{
			HasClient:                     func() bool { return true },
			GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
			KnownAddresses:                func() map[string]bool { return knownAddressesFromSnapshot(snapshot) },
			RequestSigningApproval: func(_, _, _, _ string, _, _ uint64, violations []signerapproval.Violation, _ time.Duration) (bool, error) {
				got = violations
				return true, nil
			},
		}
		if err := svc.RequestGroupApprovalWithContext(context.Background(), req, plan, description, 0, 0, txns); err != nil {
			t.Fatal(err)
		}
		// Policy has no list for a position this request doesn't sign.
		if listed := listedRekeyTargetsForPlan(plan); listed != nil {
			t.Fatalf("policy was given a list for a position it doesn't judge: %v", listed)
		}
		return description, got
	}

	t.Run("held", func(t *testing.T) {
		description, violations := review(t, account)
		for _, want := range []string{
			"[MULTI-PARTY: 1 to sign, 1 not signed in this request (1 from this signer's accounts)]",
			"--- Transaction 1 of 2 [THIS SIGNER'S ACCOUNT - not signed in this request] ---",
			"--- Transaction 2 of 2 ---",
		} {
			if !strings.Contains(description, want) {
				t.Errorf("the review lacks %q:\n%s", want, description)
			}
		}
		if strings.Contains(description, "FOREIGN") {
			t.Errorf("the review calls the signer's own account foreign:\n%s", description)
		}
		if len(violations) != 1 || !strings.Contains(violations[0].Message, "rekey-to list") ||
			!strings.Contains(violations[0].Message, "LEAVES THIS SIGNER'S CUSTODY") || strings.Contains(violations[0].Message, "LOSE CONTROL") {
			t.Fatalf("warnings = %+v, want the listed handover", violations)
		}
	})

	t.Run("not held", func(t *testing.T) {
		description, violations := review(t, stranger)
		for _, want := range []string{
			"[MULTI-PARTY: 1 to sign, 1 foreign (not signing)]",
			"--- Transaction 1 of 2 [FOREIGN - not signing] ---",
		} {
			if !strings.Contains(description, want) {
				t.Errorf("the review lacks %q:\n%s", want, description)
			}
		}
		if strings.Contains(description, "THIS SIGNER'S ACCOUNT") {
			t.Errorf("the review claims an account the signer doesn't hold:\n%s", description)
		}
		if len(violations) != 1 || !strings.Contains(violations[0].Message, "LOSE CONTROL") {
			t.Fatalf("warnings = %+v, want the unlisted rekey warning", violations)
		}
	})
}

// Both requests that carry such a position fill it in: /sign from the sender,
// and /sign/component from the key its context position names.
func TestPlansRecogniseHeldPositionsTheyDoNotSign(t *testing.T) {
	falcon := types.Address{7}
	service, authorizer, txn := frozenBoundedTestServiceWith(t, 4_500, map[string]string{falcon.String(): nativefalcon.KeyType})
	other := func(sender types.Address) types.Transaction {
		return types.Transaction{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: sender, Fee: 1_000, FirstValid: 1, LastValid: 10, GenesisHash: txn.GenesisHash},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
		}
	}
	plan := func(sender types.Address) *PlanResult {
		planned, err := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
			{AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)},
			{TxnBytesHex: txnutil.EncodeWithPrefixHex(other(sender)), PQScheme: signerapi.PQSchemeFalcon1024},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return planned
	}
	if held := plan(falcon); !held.ForeignIndices[1] || held.HeldForeign[1] == nil || len(held.HeldForeign) != 1 {
		t.Fatalf("/sign with a held foreign sender: foreign=%v held=%v", held.ForeignIndices, held.HeldForeign)
	}
	if unheld := plan(types.Address{8}); !unheld.ForeignIndices[1] || unheld.HeldForeign != nil {
		t.Fatalf("/sign with an unheld foreign sender: foreign=%v held=%v", unheld.ForeignIndices, unheld.HeldForeign)
	}

	planned, planErr := service.Planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)},
		{AuthAddress: falcon.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(other(falcon))},
	}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	request := signerapi.ComponentRequest{
		Targets:             []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: authorizer}},
		ContextualPositions: []signerapi.ComponentContextPosition{{TargetIndex: 1, AuthAddress: falcon.String()}},
	}
	for i, plannedTxn := range planned.AllTxns {
		request.GroupBytesHex = append(request.GroupBytesHex, txnutil.EncodeWithPrefixHex(plannedTxn))
		if i > 1 {
			request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
		}
	}
	reconstructed, _, err := service.ValidateFrozenComponentContext(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed.ForeignIndices[1] || reconstructed.HeldForeign[1] == nil || len(reconstructed.HeldForeign) != 1 {
		t.Fatalf("/sign/component with a held context position: foreign=%v held=%v", reconstructed.ForeignIndices, reconstructed.HeldForeign)
	}
}

// A held key the request names for another sender is the request's claim. The
// signer can't check it here, so the review says who named it, keeps the
// unlisted-rekey warning, and doesn't count the position among its accounts. A
// client can't use one of the signer's accounts to soften a stranger's rekey.
func TestGroupReviewDoesNotVouchForANamedAuthorizer(t *testing.T) {
	account, native, stranger := listTestRekey(listTestTarget).Sender, types.Address{0x71}, types.Address{0x72}
	snapshot := heldTestSnapshot(t, account, native)
	rekey := listTestRekey(listTestTarget)
	rekey.Sender, rekey.Receiver = stranger, stranger
	payment := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: native, Fee: 1_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
	}
	txns := []types.Transaction{rekey, payment}
	foreign := map[int]bool{0: true}
	plan := &PlanResult{
		AllTxns: txns, ForeignIndices: foreign, HasForeign: true,
		PassthroughIndices: map[int]bool{}, BoundedItems: make([]*boundedPlanItem, 2),
		HeldForeign: heldForeignPositions(snapshot, txns, foreign, map[int]string{0: account.String()}),
	}
	if plan.HeldForeign[0] == nil || plan.HeldForeign[0].NamedAuthorizer != account.String() {
		t.Fatalf("held = %+v", plan.HeldForeign[0])
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{TxnBytesHex: "00"}, {AuthAddress: native.String()}}}
	description, _, _ := BuildApprovalDescription(req, plan, txns, func(types.Transaction) string { return "txn\n" })
	for _, want := range []string{
		"[MULTI-PARTY: 1 to sign, 1 foreign (not signing)]",
		"--- Transaction 1 of 2 [NOT SIGNED IN THIS REQUEST - authorizer named by the request] ---",
		"  Named authorizer: " + account.String() + " (this signer holds it; not checked against the chain)",
	} {
		if !strings.Contains(description, want) {
			t.Errorf("the review lacks %q:\n%s", want, description)
		}
	}
	if strings.Contains(description, "THIS SIGNER'S ACCOUNT") {
		t.Errorf("the review vouches for a sender the signer doesn't hold:\n%s", description)
	}
	var got []signerapproval.Violation
	svc := &ApprovalService{
		HasClient:                     func() bool { return true },
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		KnownAddresses:                func() map[string]bool { return knownAddressesFromSnapshot(snapshot) },
		RequestSigningApproval: func(_, _, _, _ string, _, _ uint64, violations []signerapproval.Violation, _ time.Duration) (bool, error) {
			got = violations
			return true, nil
		},
	}
	if err := svc.RequestGroupApprovalWithContext(context.Background(), req, plan, description, 0, 0, txns); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0].Message, "LOSE CONTROL") || strings.Contains(got[0].Message, "rekey-to list") {
		t.Fatalf("warnings = %+v, want the unlisted rekey warning", got)
	}
}
