// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
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

// A foreign position is recognised from the signer's records. The sender comes
// first: a sender whose key the signer holds is recognised whatever the request
// names. A held key named for another sender is recorded as the request's claim.
// An address the signer doesn't hold stays foreign whatever the request says, and
// a position the request signs is never one.
func TestHeldForeignPositionsComeFromTheSignersRecords(t *testing.T) {
	account, native, stranger := listTestRekey(listTestTarget).Sender, types.Address{0x71}, types.Address{0x72}
	unheld := types.Address{0x73}.String()
	snapshot := heldTestSnapshot(t, account, native)
	from := func(sender types.Address) types.Transaction {
		txn := listTestRekey(listTestTarget)
		txn.Sender = sender
		return txn
	}
	txns := []types.Transaction{
		from(account), from(native), from(stranger), from(account),
		from(stranger), from(stranger), from(account), from(account), from(account),
	}
	foreign := map[int]bool{0: true, 1: true, 2: true, 4: true, 5: true, 6: true, 7: true, 8: true}
	holders := map[int]string{4: account.String(), 5: unheld, 6: native.String(), 7: unheld, 8: account.String()}
	held := heldForeignPositions(snapshot, txns, foreign, holders)
	listed := func(position *heldPosition) bool {
		return position != nil && position.ListedRekeyTargets[listTestTarget.String()]
	}

	for i, want := range map[int]heldPosition{
		// A held account with a list, and a held native key without one.
		0: {SenderHeld: true},
		1: {SenderHeld: true},
		// The request names a held account for another sender. That is the
		// request's word: it is recorded as such, and gives the warnings no list.
		4: {NamedAuthorizer: account.String()},
		// A held sender for which the request names another held key. Both are
		// recorded. By the request's own account the sender's program doesn't
		// authorize the position, so its list isn't used.
		6: {SenderHeld: true, NamedAuthorizer: native.String()},
		// A held sender stays recognised when the named key isn't held, or is
		// the sender itself.
		7: {SenderHeld: true},
		8: {SenderHeld: true},
	} {
		got := held[i]
		if got == nil || got.SenderHeld != want.SenderHeld || got.NamedAuthorizer != want.NamedAuthorizer || got.ListUnreadable {
			t.Errorf("position %d = %+v, want %+v", i, got, want)
		}
	}
	for i, want := range map[int]bool{0: true, 1: false, 4: false, 6: false, 7: true, 8: true} {
		if listed(held[i]) != want {
			t.Errorf("position %d: rekey-to list present = %v, want %v", i, listed(held[i]), want)
		}
	}
	if held[2] != nil || held[5] != nil {
		t.Errorf("an address the signer doesn't hold was recognised: %+v, %+v", held[2], held[5])
	}
	if held[3] != nil {
		t.Errorf("a position the request signs was recognised as one it doesn't: %+v", held[3])
	}
	if len(held) != 6 || sendersHeld(held) != 5 {
		t.Errorf("held = %d positions, %d by sender; want 6 and 5", len(held), sendersHeld(held))
	}
	if got := heldForeignPositions(snapshot, txns, nil, nil); got != nil {
		t.Errorf("a request with no foreign position: %v", got)
	}
	if got := heldForeignPositions(PlannerRuntimeSnapshot{}, txns, foreign, holders); got != nil {
		t.Errorf("a signer with no keys: %v", got)
	}

	// A stored list that doesn't read is said, not hidden: the request that
	// signs the position fails on it.
	broken := heldTestSnapshot(t, account, native)
	metadata := broken.KeyMetadata[account.String()]
	metadata.Parameters = map[string]string{boundedmeta.RekeyListEntriesParameter: "not-an-address"}
	broken.KeyMetadata[account.String()] = metadata
	got := heldForeignPositions(broken, txns[:1], map[int]bool{0: true}, nil)[0]
	if got == nil || !got.SenderHeld || !got.ListUnreadable || got.ListedRekeyTargets != nil {
		t.Fatalf("an unreadable list: %+v", got)
	}
	if _, lines := heldPositionHeading(got); len(lines) != 1 || !strings.Contains(lines[0], "rekey-to list could not be read") {
		t.Fatalf("the review doesn't say the list is unreadable: %q", lines)
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
			"[MULTI-PARTY: 1 to sign, 1 not signed in this request: 1 whose key this signer holds, 0 foreign]",
			"--- Transaction 1 of 2 [THIS SIGNER HOLDS THIS ACCOUNT'S KEY - not signed in this request] ---",
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
		if strings.Contains(description, "THIS SIGNER HOLDS") {
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
	if strings.Contains(description, "THIS SIGNER HOLDS THIS ACCOUNT'S KEY") {
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

// The group line keeps the foreign positions counted as foreign beside the ones
// whose key this signer holds, and a position the request only names an
// authorizer for counts as foreign. A held sender the request names another held
// key for is headed by what the signer knows, with the claim under it, and its
// rekey warning takes no list.
func TestGroupReviewCountsHeldAndForeignPositionsApart(t *testing.T) {
	account, native, stranger := listTestRekey(listTestTarget).Sender, types.Address{0x71}, types.Address{0x72}
	snapshot := heldTestSnapshot(t, account, native)
	from := func(sender types.Address) types.Transaction {
		txn := listTestRekey(listTestTarget)
		txn.Sender, txn.Receiver = sender, sender
		return txn
	}
	payment := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: native, Fee: 1_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{3}, Amount: 1},
	}
	txns := []types.Transaction{from(account), from(stranger), from(stranger), from(account), payment}
	foreign := map[int]bool{0: true, 1: true, 2: true, 3: true}
	plan := &PlanResult{
		AllTxns: txns, ForeignIndices: foreign, HasForeign: true,
		PassthroughIndices: map[int]bool{}, BoundedItems: make([]*boundedPlanItem, len(txns)),
		HeldForeign: heldForeignPositions(snapshot, txns, foreign, map[int]string{2: account.String(), 3: native.String()}),
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{TxnBytesHex: "00"}, {TxnBytesHex: "00"}, {TxnBytesHex: "00"}, {TxnBytesHex: "00"}, {AuthAddress: native.String()},
	}}
	description, _, _ := BuildApprovalDescription(req, plan, txns, func(types.Transaction) string { return "txn\n" })
	for _, want := range []string{
		"[MULTI-PARTY: 1 to sign, 4 not signed in this request: 2 whose key this signer holds, 2 foreign]",
		"--- Transaction 1 of 5 [THIS SIGNER HOLDS THIS ACCOUNT'S KEY - not signed in this request] ---\ntxn",
		"--- Transaction 2 of 5 [FOREIGN - not signing] ---",
		"--- Transaction 3 of 5 [NOT SIGNED IN THIS REQUEST - authorizer named by the request] ---\n  Named authorizer: " + account.String(),
		"--- Transaction 4 of 5 [THIS SIGNER HOLDS THIS ACCOUNT'S KEY - not signed in this request] ---\n  Named authorizer: " + native.String(),
		"--- Transaction 5 of 5 ---",
	} {
		if !strings.Contains(description, want) {
			t.Errorf("the review lacks %q:\n%s", want, description)
		}
	}
	listed := warningRekeyTargetsForPlan(plan)
	if !listed[0][listTestTarget.String()] || len(listed) != 1 {
		t.Fatalf("warning lists = %v, want only position 0's", listed)
	}
}
