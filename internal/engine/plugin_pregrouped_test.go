// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// signedGroup builds an offline signed group: one self-payment per note, grouped
// and signed by a fresh account. No chain access. Returns the base64 signed blobs
// (as a plugin would emit) and the decoded SignedTxns.
func signedGroup(t *testing.T, notes ...string) ([]string, []types.SignedTxn) {
	t.Helper()
	acct := crypto.GenerateAccount()
	sp := types.SuggestedParams{
		Fee:             1000,
		FirstRoundValid: 1,
		LastRoundValid:  1001,
		GenesisHash:     make([]byte, 32),
		GenesisID:       "pregrouped-test",
		FlatFee:         true,
	}
	txns := make([]types.Transaction, len(notes))
	for i, note := range notes {
		txn, err := transaction.MakePaymentTxn(acct.Address.String(), acct.Address.String(), 0, []byte(note), "", sp)
		if err != nil {
			t.Fatalf("make txn %d: %v", i, err)
		}
		txns[i] = txn
	}
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("compute group id: %v", err)
	}
	for i := range txns {
		txns[i].Group = gid
	}
	encoded := make([]string, len(txns))
	stxns := make([]types.SignedTxn, len(txns))
	for i, txn := range txns {
		_, raw, err := crypto.SignTransaction(acct.PrivateKey, txn)
		if err != nil {
			t.Fatalf("sign txn %d: %v", i, err)
		}
		encoded[i] = base64.StdEncoding.EncodeToString(raw)
		var st types.SignedTxn
		if err := msgpack.Decode(raw, &st); err != nil {
			t.Fatalf("decode txn %d: %v", i, err)
		}
		stxns[i] = st
	}
	return encoded, stxns
}

func TestProcessSignedTransactionIntents(t *testing.T) {
	encoded, want := signedGroup(t, "a", "b")

	stxns, raw, err := decodeSignedTxnIntents(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stxns) != 2 || len(raw) != 2 {
		t.Fatalf("got %d stxns, %d raw; want 2,2", len(stxns), len(raw))
	}
	// Raw bytes must be preserved verbatim (re-base64 must round-trip exactly).
	for i := range raw {
		if base64.StdEncoding.EncodeToString(raw[i]) != encoded[i] {
			t.Fatalf("raw bytes for txn %d not preserved", i)
		}
		if stxns[i].Txn.Group != want[i].Txn.Group {
			t.Fatalf("decoded txn %d group mismatch", i)
		}
	}

	t.Run("empty", func(t *testing.T) {
		if _, _, err := decodeSignedTxnIntents(nil); err == nil {
			t.Fatal("want error for empty intents")
		}
	})
	t.Run("blank entry", func(t *testing.T) {
		if _, _, err := decodeSignedTxnIntents([]string{""}); err == nil {
			t.Fatal("want error for blank encoded entry")
		}
	})
	t.Run("bad base64", func(t *testing.T) {
		if _, _, err := decodeSignedTxnIntents([]string{"!!!not base64!!!"}); err == nil {
			t.Fatal("want error for bad base64")
		}
	})
	t.Run("bad msgpack", func(t *testing.T) {
		junk := base64.StdEncoding.EncodeToString([]byte("not msgpack"))
		if _, _, err := decodeSignedTxnIntents([]string{junk}); err == nil {
			t.Fatal("want error for bad msgpack")
		}
	})
}

func TestValidatePregroupedSigned(t *testing.T) {
	t.Run("valid group passes", func(t *testing.T) {
		_, stxns := signedGroup(t, "a", "b")
		if err := validatePregroupedSigned(stxns); err != nil {
			t.Fatalf("valid group rejected: %v", err)
		}
	})

	t.Run("empty rejects", func(t *testing.T) {
		if err := validatePregroupedSigned(nil); err == nil {
			t.Fatal("want error for empty group")
		}
	})

	t.Run("single txn rejects", func(t *testing.T) {
		_, stxns := signedGroup(t, "solo")
		if err := validatePregroupedSigned(stxns); err == nil {
			t.Fatal("want error for single-txn group")
		}
	})

	t.Run("missing group id rejects", func(t *testing.T) {
		_, stxns := signedGroup(t, "a", "b")
		stxns[0].Txn.Group = types.Digest{}
		if err := validatePregroupedSigned(stxns); err == nil {
			t.Fatal("want error when a slot has no group id")
		}
	})

	t.Run("mismatched group ids reject", func(t *testing.T) {
		_, stxns := signedGroup(t, "a", "b")
		stxns[1].Txn.Group[0] ^= 0xFF
		if err := validatePregroupedSigned(stxns); err == nil {
			t.Fatal("want error when group ids differ")
		}
	})

	t.Run("tampered member (stale group id) rejects", func(t *testing.T) {
		_, stxns := signedGroup(t, "a", "b")
		// Mutate a member's body while leaving the embedded group id intact:
		// the recomputed id no longer matches, so it must be rejected, not fixed.
		stxns[0].Txn.Amount += 1
		err := validatePregroupedSigned(stxns)
		if err == nil {
			t.Fatal("want error for tampered member")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("expected group-id-mismatch error, got: %v", err)
		}
	})

	t.Run("oversized group rejects", func(t *testing.T) {
		// ComputeGroupID itself caps at MaxTxGroupSize, so build the over-limit
		// group by hand with a shared non-zero group id; the size check fires
		// before the recompute.
		var g types.Digest
		g[0] = 1
		stxns := make([]types.SignedTxn, types.MaxTxGroupSize+1)
		for i := range stxns {
			stxns[i].Txn.Group = g
		}
		if err := validatePregroupedSigned(stxns); err == nil {
			t.Fatal("want error for oversized group")
		}
	})
}

func TestDecodePregroupedSigned(t *testing.T) {
	t.Run("valid group decodes, validates, preserves bytes", func(t *testing.T) {
		encoded, _ := signedGroup(t, "a", "b")
		g, err := DecodePregroupedSigned(encoded)
		if err != nil {
			t.Fatalf("DecodePregroupedSigned: %v", err)
		}
		if len(g.Transactions()) != 2 || len(g.raw) != 2 {
			t.Fatalf("group has %d txns, %d raw; want 2,2", len(g.Transactions()), len(g.raw))
		}
		for i := range g.raw {
			if base64.StdEncoding.EncodeToString(g.raw[i]) != encoded[i] {
				t.Fatalf("raw bytes for txn %d not preserved", i)
			}
		}
	})

	t.Run("invalid group rejected at decode", func(t *testing.T) {
		encoded, _ := signedGroup(t, "solo") // single txn fails the immutability gate
		if _, err := DecodePregroupedSigned(encoded); err == nil {
			t.Fatal("want error for single-txn group")
		}
		if _, err := DecodePregroupedSigned([]string{"!!!"}); err == nil {
			t.Fatal("want error for bad base64")
		}
	})
}

func TestSubmitPregroupedSignedRejectsUnsupportedConsensusBeforeBroadcast(t *testing.T) {
	encoded, _ := signedGroup(t, "a", "b")
	group, err := DecodePregroupedSigned(encoded)
	if err != nil {
		t.Fatalf("DecodePregroupedSigned() error = %v", err)
	}
	client, server := consensusTestAlgod(t, string(protocol.ConsensusV41), nil)
	defer server.Close()
	eng, err := NewEngine("test", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	_, err = eng.SubmitPregroupedSigned(context.Background(), group)
	if err == nil || !strings.Contains(err.Error(), "network consensus") {
		t.Fatalf("SubmitPregroupedSigned() error = %v, want unsupported-consensus rejection", err)
	}
}
