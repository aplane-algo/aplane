// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// rekeyTargetTestSnapshot holds an ed25519 account and a second one, both
// valid rekey targets, an HTLC account and a key with no metadata, neither a
// valid rekey target, and a rotating account.
func rekeyTargetTestSnapshot() (PlannerRuntimeSnapshot, map[string]types.Address) {
	addrs := map[string]types.Address{
		"plain": {1}, "valid": {2}, "htlc": {3}, "bare": {4}, "rotating": {5}, "foreign": {6},
	}
	snapshot := PlannerRuntimeSnapshot{
		KeyFiles: map[string]string{}, KeyTypes: map[string]string{}, KeyMetadata: map[string]PlannerKeyMetadata{},
	}
	add := func(name, keyType string, metadata *PlannerKeyMetadata) {
		address := addrs[name].String()
		snapshot.KeyFiles[address] = name + ".key"
		snapshot.KeyTypes[address] = keyType
		if metadata != nil {
			snapshot.KeyMetadata[address] = *metadata
		}
	}
	add("plain", "ed25519", &PlannerKeyMetadata{Category: keys.CategoryEd25519, ValidRekeyTarget: true})
	add("valid", "ed25519", &PlannerKeyMetadata{Category: keys.CategoryEd25519, ValidRekeyTarget: true})
	add("htlc", "aplane.htlc.v1", &PlannerKeyMetadata{Category: keys.CategoryGenericLsig})
	add("bare", "ed25519", nil)
	add("rotating", rotatingkey.RotatingTripleWotscV1, &PlannerKeyMetadata{Category: keys.CategoryRotatingLsig})
	return snapshot, addrs
}

// A rekey to an address this signer holds an aplane key for is refused when
// that key's type is not a valid rekey target, and a key with no metadata is
// not one. A foreign target is left to the rekeys setting, a rekey to the
// account's own address passes, a position this signer doesn't sign is not
// judged, and a rotating target meets its own invariant first.
func TestRejectRekeyToInvalidTarget(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot { return snapshot }}}
	rekey := func(from, to string) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a[from], RekeyTo: a[to]}}
	}
	for _, tc := range []struct {
		name string
		txn  types.Transaction
		want string // "" when nothing is refused
	}{
		{"held valid rekey target", rekey("plain", "valid"), ""},
		{"held HTLC account", rekey("plain", "htlc"), "transaction 1: " + rekeyTargetNotValid(a["htlc"].String(), "aplane.htlc.v1").Message},
		{"held key with no metadata", rekey("plain", "bare"), "transaction 1: " + rekeyTargetNotValid(a["bare"].String(), "ed25519").Message},
		{"foreign target", rekey("plain", "foreign"), ""},
		{"an HTLC account back to its own address", rekey("htlc", "htlc"), ""},
		{"no rekey", types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a["plain"]}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.rejectSignerInvariants([]types.Transaction{tc.txn}, []int{0})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || err.HTTPStatus() != 403 || err.Code() != signerapi.ErrCodeRekeyTargetNotValid || err.Message != tc.want {
				t.Fatalf("err = %v, want 403 %s %q", err, signerapi.ErrCodeRekeyTargetNotValid, tc.want)
			}
			if strings.Contains(err.Message, "foreign") {
				t.Fatalf("message %q calls a held target foreign", err.Message)
			}
		})
	}
	// Positions this signer doesn't sign are not judged.
	if err := svc.rejectSignerInvariants([]types.Transaction{rekey("plain", "htlc")}, nil); err != nil {
		t.Fatalf("an unsigned position was judged: %v", err)
	}
	// A rotating target is refused by the rotating invariant, unchanged.
	err := svc.rejectSignerInvariants([]types.Transaction{rekey("plain", "rotating")}, []int{0})
	if want := "transaction 1: " + rotatingkey.RekeyTargetRefusal(a["rotating"].String()); err == nil || err.Message != want {
		t.Fatalf("rekey to a rotating account: err = %v, want %q", err, want)
	}
}

// A request that rekeys no account to another address takes no key snapshot.
func TestRejectRekeyToInvalidTargetTakesNoSnapshotWithoutARekey(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	calls := 0
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot { calls++; return snapshot }}}
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Sender: a["plain"]}},
		{Type: types.PaymentTx, Header: types.Header{Sender: a["htlc"], RekeyTo: a["htlc"]}},
	}
	if err := svc.rejectRekeyToInvalidTarget(txns, []int{0, 1}); err != nil || calls != 0 {
		t.Fatalf("err = %v, snapshot calls = %d; want no refusal and no snapshot", err, calls)
	}
	txns[0].RekeyTo = a["valid"]
	if err := svc.rejectRekeyToInvalidTarget(txns, []int{0, 1}); err != nil || calls != 1 {
		t.Fatalf("err = %v, snapshot calls = %d; want no refusal and one snapshot", err, calls)
	}
}

// A position this signer does not sign is never refused by the invariant, so
// the group's warning says what its rekey target is: a held aplane key that
// is not a valid rekey target, and for a generic LogicSig, that its program
// decides what can be signed.
func TestGroupWarningNamesAHeldInvalidRekeyTargetAtAForeignPosition(t *testing.T) {
	snapshot, a := rekeyTargetTestSnapshot()
	foreignRekey := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: a["foreign"], Fee: 1_000, RekeyTo: a["htlc"]},
	}
	payment := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: a["plain"], Fee: 1_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: a["valid"], Amount: 1},
	}
	txns := []types.Transaction{payment, foreignRekey}
	for _, class := range []string{"foreign", "passthrough"} {
		t.Run(class, func(t *testing.T) {
			plan := &PlanResult{AllTxns: txns, ForeignIndices: map[int]bool{}, PassthroughIndices: map[int]bool{}, BoundedItems: make([]*boundedPlanItem, 2)}
			if class == "foreign" {
				plan.ForeignIndices[1], plan.HasForeign = true, true
			} else {
				plan.PassthroughIndices[1], plan.HasPassthrough = true, true
			}
			var got []signerapproval.Violation
			svc := &ApprovalService{
				HasClient:                     func() bool { return true },
				GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
				KnownAddresses:                func() map[string]bool { return knownAddressesFromSnapshot(snapshot) },
				InvalidRekeyTargets:           func() map[string]txnreview.InvalidRekeyTarget { return invalidRekeyTargetsForTest(snapshot) },
				RequestSigningApproval: func(_, _, _, _ string, _, _ uint64, violations []signerapproval.Violation, _ time.Duration) (bool, error) {
					got = violations
					return true, nil
				},
			}
			req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: a["plain"].String()}, {TxnBytesHex: "00"}}}
			if err := svc.RequestGroupApprovalWithContext(context.Background(), req, plan, "group", 0, 0, txns); err != nil {
				t.Fatal(err)
			}
			want := txnreview.RekeyTransfersText + "\n   " + txnreview.RekeyHeldNotValidText(txnreview.InvalidRekeyTarget{KeyType: "aplane.htlc.v1", GenericLogicSig: true}) +
				"\n   " + txnreview.RekeyGenericLogicSigText
			for _, v := range got {
				if v.Field == "Tx 2/2: RekeyTo" {
					if v.Message != want {
						t.Fatalf("rekey warning = %q, want %q", v.Message, want)
					}
					return
				}
			}
			t.Fatalf("no rekey warning for the %s position: %+v", class, got)
		})
	}
}

// invalidRekeyTargetsForTest builds the runtime's InvalidRekeyTargets from a
// planner snapshot, as Runtime.InvalidRekeyTargets builds it from the key
// index.
func invalidRekeyTargetsForTest(snapshot PlannerRuntimeSnapshot) map[string]txnreview.InvalidRekeyTarget {
	out := map[string]txnreview.InvalidRekeyTarget{}
	for address := range snapshot.KeyFiles {
		metadata := snapshot.KeyMetadata[address]
		if metadata.ValidRekeyTarget {
			continue
		}
		out[address] = txnreview.InvalidRekeyTarget{KeyType: snapshot.KeyTypes[address], GenericLogicSig: metadata.Category == keys.CategoryGenericLsig}
	}
	return out
}
