// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
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
		{"held HTLC account", rekey("plain", "htlc"), "transaction 1: " + rekeyTargetNotValidRefusal(a["htlc"].String(), "aplane.htlc.v1")},
		{"held key with no metadata", rekey("plain", "bare"), "transaction 1: " + rekeyTargetNotValidRefusal(a["bare"].String(), "ed25519")},
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
			if err == nil || err.HTTPStatus() != 403 || err.Message != tc.want {
				t.Fatalf("err = %v, want 403 %q", err, tc.want)
			}
			if !strings.Contains(err.Message, RekeyTargetNotValidReason+": ") || strings.Contains(err.Message, "foreign") {
				t.Fatalf("message %q does not carry its own reason, or calls a held target foreign", err.Message)
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
