// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
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

func TestSubmitPluginTransactionsRejectsLocalSigners(t *testing.T) {
	app := &App{}
	_, err := app.SubmitPluginTransactions(context.Background(), "plugin", &jsonrpc.ExecuteResult{
		LocalSigners: []json.RawMessage{json.RawMessage(`{"address":"A","secretKey":"k"}`)},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "localSigners are not supported") {
		t.Fatalf("want localSigners unsupported error, got %v", err)
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
		wantSub string
	}{
		{
			name:    "no pluginSigners",
			signers: nil,
			wantSub: "requires pluginSigners",
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
		{
			name: "LogicSig and native PQ are mutually exclusive",
			signers: []jsonrpc.PluginSigner{{
				Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r",
				LsigResources: &jsonrpc.PluginLogicSigResources{ProgramBytes: 1, MaxOpcodeCost: 1},
				PQScheme:      "f1",
			}},
			wantSub: "cannot specify both pq_scheme and lsig_resources",
		},
		{
			name: "unsupported native PQ scheme",
			signers: []jsonrpc.PluginSigner{{
				Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r", PQScheme: "f2",
			}},
			wantSub: `unsupported pq_scheme "f2"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePresignPlan, PluginSigners: tc.signers}
			_, err := app.SubmitPluginTransactions(ctx, "plugin", result, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}
