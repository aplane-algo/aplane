// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestProcessTransactionIntentsRawClearsGroupID(t *testing.T) {
	var group types.Digest
	group[0] = 1
	group[31] = 9

	addr := testAddr(1)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: mustDecodeAddressForPluginTxnTest(t, addr),
			Group:  group,
			Fee:    types.MicroAlgos(1000),
		},
	}

	intents := []jsonrpc.TransactionIntent{
		{
			Type:    "raw",
			Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn)),
		},
	}

	got, err := ProcessTransactionIntents(intents)
	if err != nil {
		t.Fatalf("ProcessTransactionIntents() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].Sender != txn.Sender {
		t.Fatalf("sender = %s, want %s", got[0].Sender.String(), txn.Sender.String())
	}
	if got[0].Group != (types.Digest{}) {
		t.Fatalf("group = %v, want zero digest", got[0].Group)
	}
}

func TestProcessTransactionIntentsRejectsBadInputs(t *testing.T) {
	tests := []struct {
		name        string
		intents     []jsonrpc.TransactionIntent
		errContains string
	}{
		{
			name: "missing encoded raw txn",
			intents: []jsonrpc.TransactionIntent{
				{Type: "raw"},
			},
			errContains: "transaction 1: missing encoded data",
		},
		{
			name: "invalid base64 raw txn",
			intents: []jsonrpc.TransactionIntent{
				{Type: "raw", Encoded: "!!!"},
			},
			errContains: "transaction 1: failed to decode base64",
		},
		{
			name: "invalid msgpack raw txn",
			intents: []jsonrpc.TransactionIntent{
				{Type: "raw", Encoded: base64.StdEncoding.EncodeToString([]byte("not-msgpack"))},
			},
			errContains: "transaction 1: failed to decode msgpack",
		},
		{
			name: "unsupported intent type",
			intents: []jsonrpc.TransactionIntent{
				{Type: "mystery"},
			},
			errContains: "transaction 1: unsupported type mystery",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ProcessTransactionIntents(tt.intents)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errContains)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestProcessTransactionIntentsMultipleRawAndLaterFailure(t *testing.T) {
	txn1 := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: mustDecodeAddressForPluginTxnTest(t, testAddr(31)),
			Fee:    types.MicroAlgos(1000),
		},
	}
	txn2 := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: mustDecodeAddressForPluginTxnTest(t, testAddr(32)),
			Fee:    types.MicroAlgos(1000),
		},
	}

	got, err := ProcessTransactionIntents([]jsonrpc.TransactionIntent{
		{Type: "raw", Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn1))},
		{Type: "raw", Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn2))},
	})
	if err != nil {
		t.Fatalf("ProcessTransactionIntents(valid multiple) error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}

	_, err = ProcessTransactionIntents([]jsonrpc.TransactionIntent{
		{Type: "raw", Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn1))},
		{Type: "raw", Encoded: "%%%"},
	})
	if err == nil {
		t.Fatal("expected error on later invalid transaction, got nil")
	}
	if !strings.Contains(err.Error(), "transaction 2: failed to decode base64") {
		t.Fatalf("error = %q, want transaction 2 decode failure", err.Error())
	}
}

func mustDecodeAddressForPluginTxnTest(t *testing.T, addr string) types.Address {
	t.Helper()
	decoded, err := types.DecodeAddress(addr)
	if err != nil {
		t.Fatalf("DecodeAddress(%q) error = %v", addr, err)
	}
	return decoded
}
