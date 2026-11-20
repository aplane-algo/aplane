// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
)

func TestDecorateRekeyResultForSignableLsigTarget(t *testing.T) {
	result := &RekeyCommandResult{
		From:                    "FROM",
		To:                      "TO",
		CanSignForTarget:        true,
		TargetAuthorizationKind: algorithm.AuthorizationLogicSig,
	}

	decorateRekeyResult(result)

	if len(result.PreSubmitLines) == 0 {
		t.Fatal("PreSubmitLines empty")
	}
	if got, want := result.ConfirmedLines[0], "Account {from} is now rekeyed to lsig {to}"; got != want {
		t.Fatalf("ConfirmedLines[0] = %q, want %q", got, want)
	}
}

func TestDecorateRekeyResultForExternalTarget(t *testing.T) {
	result := &RekeyCommandResult{
		From:             "FROM",
		To:               "TO",
		CanSignForTarget: false,
	}

	decorateRekeyResult(result)

	if len(result.PreSubmitLines) == 0 {
		t.Fatal("PreSubmitLines empty")
	}
	if got, want := result.PreSubmitLines[1], "Target address: {to}"; got != want {
		t.Fatalf("PreSubmitLines[1] = %q, want %q", got, want)
	}
	if got, want := result.PendingLines[0], "Target is an address you cannot sign for - you'll need the new auth address's private key to sign."; got != want {
		t.Fatalf("PendingLines[0] = %q, want %q", got, want)
	}
}

func TestDecorateRekeyResultForSignableNativePQTarget(t *testing.T) {
	result := &RekeyCommandResult{
		From:                    "FROM",
		To:                      "TO",
		CanSignForTarget:        true,
		TargetAuthorizationKind: algorithm.AuthorizationNativePQ,
	}

	decorateRekeyResult(result)

	if got, want := result.ConfirmedLines[0], "Account {from} is now rekeyed to native post-quantum address {to}"; got != want {
		t.Fatalf("ConfirmedLines[0] = %q, want %q", got, want)
	}
}

// A signable target is named by its kind in all three lines: before
// signing as an address of that kind, and once in effect as the lsig itself
// or an address of the kind. A kind without its own name is Ed25519's.
func TestDecorateRekeyResultNamesTheTargetKind(t *testing.T) {
	tests := []struct {
		kind                          algorithm.AuthorizationKind
		preSubmit, confirmed, pending string
	}{
		{algorithm.AuthorizationLogicSig, "Rekeying account {from} to lsig address {to}...",
			"Account {from} is now rekeyed to lsig {to}", "When confirmed, {from} will be rekeyed to lsig {to}"},
		{algorithm.AuthorizationNativePQ, "Rekeying account {from} to native post-quantum address {to}...",
			"Account {from} is now rekeyed to native post-quantum address {to}", "When confirmed, {from} will be rekeyed to native post-quantum address {to}"},
		{algorithm.AuthorizationEd25519, "Rekeying account {from} to Ed25519 address {to}...",
			"Account {from} is now rekeyed to Ed25519 address {to}", "When confirmed, {from} will be rekeyed to Ed25519 address {to}"},
		{"", "Rekeying account {from} to Ed25519 address {to}...",
			"Account {from} is now rekeyed to Ed25519 address {to}", "When confirmed, {from} will be rekeyed to Ed25519 address {to}"},
	}
	for _, tt := range tests {
		result := &RekeyCommandResult{From: "FROM", To: "TO", CanSignForTarget: true, TargetAuthorizationKind: tt.kind}
		decorateRekeyResult(result)
		want := []string{tt.preSubmit, "WARNING: After this transaction, you must use the new auth address to sign!"}
		if !reflect.DeepEqual(result.PreSubmitLines, want) ||
			!reflect.DeepEqual(result.ConfirmedLines, []string{tt.confirmed}) ||
			!reflect.DeepEqual(result.PendingLines, []string{tt.pending}) {
			t.Errorf("kind %q: lines = %q / %q / %q", tt.kind, result.PreSubmitLines, result.ConfirmedLines, result.PendingLines)
		}
	}
}

func TestDecorateRekeyResultForUnrekey(t *testing.T) {
	result := &RekeyCommandResult{
		From:               "FROM",
		CurrentAuthAddress: "AUTH",
		IsUnrekey:          true,
	}

	decorateRekeyResult(result)

	if got, want := result.PreSubmitLines[0], "Account is currently rekeyed to: {current_auth}"; got != want {
		t.Fatalf("PreSubmitLines[0] = %q, want %q", got, want)
	}
	if got, want := result.ConfirmedLines[0], "Account {from} is now back to normal (no rekey in effect)"; got != want {
		t.Fatalf("ConfirmedLines[0] = %q, want %q", got, want)
	}
}
