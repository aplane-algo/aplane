// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
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
			errContains: `transaction 1: unsupported type "mystery"`,
		},
		{
			// The kind is the plugin's text: quoted, so it cannot act on a
			// terminal when the error is printed.
			name: "intent kind with control bytes",
			intents: []jsonrpc.TransactionIntent{
				{Type: "raw\x1b[2J"},
			},
			errContains: `transaction 1: unsupported type "raw\x1b[2J"`,
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

// A grouped pair, as an SDK composer (algosdk's AtomicTransactionComposer, which
// the reti example plugin uses) returns it in the default mode: the group ID is
// read as the plugin set it, and cleared for the signer to compute.
func TestProcessTransactionIntentsAcceptsAComposerGroupedPair(t *testing.T) {
	txns := []types.Transaction{pluginIntentTestPayment(t, 41, 1), pluginIntentTestPayment(t, 42, 2)}
	groupID, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	intents := make([]jsonrpc.TransactionIntent, len(txns))
	for i := range txns {
		txns[i].Group = groupID
		intents[i] = jsonrpc.TransactionIntent{Type: "raw", Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txns[i]))}
	}

	drafts, err := DecodeRawTransactionIntents(intents)
	if err != nil {
		t.Fatalf("DecodeRawTransactionIntents() error = %v", err)
	}
	for i, txn := range drafts {
		if txn.Group != groupID {
			t.Fatalf("draft %d group = %x, want the plugin's %x", i, txn.Group, groupID)
		}
	}

	got, err := ProcessTransactionIntents(intents)
	if err != nil {
		t.Fatalf("ProcessTransactionIntents() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	for i, txn := range got {
		if txn.Group != (types.Digest{}) {
			t.Fatalf("transaction %d group = %x, want cleared", i, txn.Group)
		}
		want := txns[i]
		want.Group = types.Digest{}
		if !bytes.Equal(msgpack.Encode(txn), msgpack.Encode(want)) {
			t.Fatalf("transaction %d changed beyond its group ID", i)
		}
	}
}

// What is reviewed, planned and signed must be what the plugin's bytes say, so
// bytes that decode but are not the canonical encoding of what they decode to
// are refused, at the position they hold.
func TestProcessTransactionIntentsRefusesNonCanonicalEncodings(t *testing.T) {
	first := base64.StdEncoding.EncodeToString(msgpack.Encode(pluginIntentTestPayment(t, 51, 1)))
	for name, variant := range nonCanonicalTxnVariants(t) {
		t.Run(name, func(t *testing.T) {
			intents := []jsonrpc.TransactionIntent{
				{Type: "raw", Encoded: first},
				{Type: "raw", Encoded: base64.StdEncoding.EncodeToString(variant)},
			}
			for decoder, decode := range map[string]func([]jsonrpc.TransactionIntent) ([]types.Transaction, error){
				"DecodeRawTransactionIntents": DecodeRawTransactionIntents,
				"ProcessTransactionIntents":   ProcessTransactionIntents,
			} {
				_, err := decode(intents)
				if !errors.Is(err, canonical.ErrNotCanonical) || !strings.HasPrefix(err.Error(), "transaction 2: ") {
					t.Fatalf("%s error = %v, want transaction 2 refused as not canonical", decoder, err)
				}
			}
		})
	}
}

// pluginIntentTestPayment is a payment of amount from a sender to a receiver,
// both built from index.
func pluginIntentTestPayment(t *testing.T, index int, amount uint64) types.Transaction {
	t.Helper()
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     mustDecodeAddressForPluginTxnTest(t, testAddr(index)),
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1,
			LastValid:  10,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: mustDecodeAddressForPluginTxnTest(t, testAddr(index+100)),
			Amount:   types.MicroAlgos(amount),
		},
	}
}

// nonCanonicalTxnVariants returns bytes that a lenient decoder reads as a
// payment without complaint but that are not the canonical encoding of what
// it reads: a second transaction appended (dropped), the amount written twice
// (the last wins), a receiver one byte short (zero-padded) or long (truncated),
// and an explicit empty close-to address (read as absent).
func nonCanonicalTxnVariants(t *testing.T) map[string][]byte {
	t.Helper()
	payment := pluginIntentTestPayment(t, 61, 1)
	canonicalBytes := msgpack.Encode(payment)
	fields := func(receiver []byte, extra map[string]any) []byte {
		m := map[string]any{
			"amt": uint64(payment.Amount), "fee": uint64(payment.Fee), "fv": uint64(payment.FirstValid),
			"lv": uint64(payment.LastValid), "rcv": receiver, "snd": payment.Sender[:], "type": "pay",
		}
		for k, v := range extra {
			m[k] = v
		}
		return msgpack.Encode(m)
	}
	if !bytes.Equal(fields(payment.Receiver[:], nil), canonicalBytes) {
		t.Fatal("fixture: the field map does not encode as the payment does")
	}
	repeated := append([]byte{canonicalBytes[0] + 1}, canonicalBytes[1:]...)
	repeated = append(repeated, msgpack.Encode(map[string]uint64{"amt": 5_000_000})[1:]...)
	variants := map[string][]byte{
		"second transaction appended": append(append([]byte{}, canonicalBytes...), msgpack.Encode(pluginIntentTestPayment(t, 62, 5_000_000))...),
		"amount written twice":        repeated,
		"receiver one byte short":     fields(payment.Receiver[:31], nil),
		"receiver one byte long":      fields(append(append([]byte{}, payment.Receiver[:]...), 0xff), nil),
		"explicit empty close-to":     fields(payment.Receiver[:], map[string]any{"close": make([]byte, 32)}),
	}
	for name, variant := range variants {
		var lenient types.Transaction
		if err := msgpack.Decode(variant, &lenient); err != nil {
			t.Fatalf("fixture %s: a lenient decoder refuses it (%v), so it tests nothing", name, err)
		}
	}
	return variants
}

func mustDecodeAddressForPluginTxnTest(t *testing.T, addr string) types.Address {
	t.Helper()
	decoded, err := types.DecodeAddress(addr)
	if err != nil {
		t.Fatalf("DecodeAddress(%q) error = %v", addr, err)
	}
	return decoded
}
