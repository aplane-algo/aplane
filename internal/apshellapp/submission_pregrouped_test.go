// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestSubmitPluginTransactionsUnsupportedGroupMode(t *testing.T) {
	app := &App{}
	_, err := app.SubmitPluginTransactions(context.Background(), "plugin", &jsonrpc.ExecuteResult{GroupMode: "bogus"}, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported plugin groupMode") {
		t.Fatalf("want unsupported groupMode error, got %v", err)
	}
}

// TestSubmitPregroupedSignedRejections drives the dispatch with a nil engine.
// Every case here must reject before any signer/engine access — which both
// verifies the fail-closed rules and proves the pregrouped-signed path does not
// require a signer connection (a nil engine would panic if it did).
func TestSubmitPregroupedSignedRejections(t *testing.T) {
	app := &App{}
	ctx := context.Background()
	signed := jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentSigned, Encoded: "AA=="}

	tests := []struct {
		name    string
		result  *jsonrpc.ExecuteResult
		lsig    map[string][]byte
		wantSub string
	}{
		{
			name: "localSigners rejected",
			result: &jsonrpc.ExecuteResult{
				GroupMode:    jsonrpc.GroupModePregroupedSigned,
				Transactions: []jsonrpc.TransactionIntent{signed, signed},
				LocalSigners: []jsonrpc.LocalSigner{{Address: "X", SecretKey: "Y"}},
			},
			wantSub: "does not allow localSigners",
		},
		{
			name: "lsig args rejected",
			result: &jsonrpc.ExecuteResult{
				GroupMode:    jsonrpc.GroupModePregroupedSigned,
				Transactions: []jsonrpc.TransactionIntent{signed, signed},
			},
			lsig:    map[string][]byte{"k": []byte("v")},
			wantSub: "does not allow lsig args",
		},
		{
			name:    "empty transactions rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedSigned},
			wantSub: "requires transactions",
		},
		{
			name: "raw type rejected",
			result: &jsonrpc.ExecuteResult{
				GroupMode:    jsonrpc.GroupModePregroupedSigned,
				Transactions: []jsonrpc.TransactionIntent{{Type: jsonrpc.TransactionIntentRaw, Encoded: "AA=="}},
			},
			wantSub: `type "signed"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := app.SubmitPluginTransactions(ctx, "plugin", tc.result, tc.lsig)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// TestSubmitPresignPlanRejections drives presign-plan input validation with a nil
// engine; every case must reject before any engine/signer access.
func TestSubmitPresignPlanRejections(t *testing.T) {
	app := &App{}
	ctx := context.Background()

	tests := []struct {
		name    string
		signers []jsonrpc.PluginSigner
		local   []jsonrpc.LocalSigner
		wantSub string
	}{
		{
			name:    "no pluginSigners",
			signers: nil,
			wantSub: "requires pluginSigners",
		},
		{
			name:    "localSigners rejected",
			signers: []jsonrpc.PluginSigner{{Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r"}},
			local:   []jsonrpc.LocalSigner{{Address: "A", SecretKey: "k"}},
			wantSub: "does not allow localSigners",
		},
		{
			name:    "unsupported kind",
			signers: []jsonrpc.PluginSigner{{Address: "A", Kind: "bogus", SignerRef: "r"}},
			wantSub: "unsupported kind",
		},
		{
			name:    "missing signerRef",
			signers: []jsonrpc.PluginSigner{{Address: "A", Kind: jsonrpc.PluginSignerKindCallback}},
			wantSub: "missing address or signerRef",
		},
		{
			name: "duplicate address",
			signers: []jsonrpc.PluginSigner{
				{Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r1"},
				{Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r2"},
			},
			wantSub: "duplicate address",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePresignPlan, PluginSigners: tc.signers, LocalSigners: tc.local}
			_, err := app.SubmitPluginTransactions(ctx, "plugin", result, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// TestSubmitPregroupedMixedRejections drives pregrouped-mixed input validation with
// a nil engine; every case must reject before any engine/signer access.
func TestSubmitPregroupedMixedRejections(t *testing.T) {
	app := &App{}
	ctx := context.Background()
	signed := jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentSigned, Encoded: "AA=="}

	tests := []struct {
		name    string
		result  *jsonrpc.ExecuteResult
		wantSub string
	}{
		{
			name:    "localSigners rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedMixed, Transactions: []jsonrpc.TransactionIntent{signed}, LocalSigners: []jsonrpc.LocalSigner{{Address: "A", SecretKey: "k"}}},
			wantSub: "does not allow localSigners",
		},
		{
			name:    "pluginSigners rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedMixed, Transactions: []jsonrpc.TransactionIntent{signed}, PluginSigners: []jsonrpc.PluginSigner{{Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r"}}},
			wantSub: "or pluginSigners",
		},
		{
			name:    "empty transactions rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedMixed},
			wantSub: "requires transactions",
		},
		{
			name:    "raw without aplane signer rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedMixed, Transactions: []jsonrpc.TransactionIntent{{Type: jsonrpc.TransactionIntentRaw, Encoded: "AA=="}}},
			wantSub: `must declare signer "aplane"`,
		},
		{
			name:    "unsupported type rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedMixed, Transactions: []jsonrpc.TransactionIntent{{Type: "bogus", Encoded: "AA=="}}},
			wantSub: "unsupported type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := app.SubmitPluginTransactions(ctx, "plugin", tc.result, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}
