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
	_, err := app.SubmitPluginTransactions(context.Background(), &jsonrpc.ExecuteResult{GroupMode: "bogus"}, nil)
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
			_, err := app.SubmitPluginTransactions(ctx, tc.result, tc.lsig)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}
