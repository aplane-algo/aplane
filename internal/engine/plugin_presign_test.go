// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func presignTestTxn(t *testing.T, sender, note string) types.Transaction {
	t.Helper()
	sp := types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 10, LastRoundValid: 1010,
		GenesisHash: make([]byte, 32), GenesisID: "presign-test", FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(sender, sender, 0, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	return txn
}

func TestAssertPluginSlotPreserved(t *testing.T) {
	acct := crypto.GenerateAccount()
	draft := presignTestTxn(t, acct.Address.String(), "deposit")

	t.Run("only group and fee changed -> ok", func(t *testing.T) {
		canonical := draft
		canonical.Group = types.Digest{1, 2, 3}
		canonical.Fee = 5000
		if err := assertPluginSlotPreserved(draft, canonical); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*types.Transaction)
	}{
		{"sender", func(tx *types.Transaction) { tx.Sender = crypto.GenerateAccount().Address }},
		{"firstValid", func(tx *types.Transaction) { tx.FirstValid++ }},
		{"lastValid", func(tx *types.Transaction) { tx.LastValid++ }},
		{"amount", func(tx *types.Transaction) { tx.Amount++ }},
		{"lease", func(tx *types.Transaction) { tx.Lease = [32]byte{9} }},
		{"genesisHash", func(tx *types.Transaction) { tx.GenesisHash = types.Digest{7} }},
	} {
		t.Run(tc.name+" changed -> error", func(t *testing.T) {
			canonical := draft
			canonical.Group = types.Digest{1}
			canonical.Fee = 5000
			tc.mutate(&canonical)
			if err := assertPluginSlotPreserved(draft, canonical); err == nil {
				t.Fatalf("expected error when %s changed", tc.name)
			}
		})
	}
}

func TestAssertPluginSignersMatched(t *testing.T) {
	a := crypto.GenerateAccount()
	b := crypto.GenerateAccount()
	txns := []types.Transaction{
		presignTestTxn(t, a.Address.String(), "a"),
		presignTestTxn(t, b.Address.String(), "b"),
	}

	t.Run("all declared signers match -> ok", func(t *testing.T) {
		refs := map[string]string{a.Address.String(): "ref-a"}
		if err := assertPluginSignersMatched(txns, refs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unused declared signer -> error", func(t *testing.T) {
		bogus := crypto.GenerateAccount()
		refs := map[string]string{
			a.Address.String():     "ref-a",
			bogus.Address.String(): "ref-bogus", // matches no txn
		}
		if err := assertPluginSignersMatched(txns, refs); err == nil {
			t.Fatal("expected error when a declared signer matches no transaction")
		}
	})
}

func TestValidatePluginSignedSlot(t *testing.T) {
	acct := crypto.GenerateAccount()
	canonical := presignTestTxn(t, acct.Address.String(), "canonical")
	canonical.Group = types.Digest{4, 2}

	sign := func(txn types.Transaction) string {
		_, raw, err := crypto.SignTransaction(acct.PrivateKey, txn)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}

	t.Run("signs exact canonical -> ok", func(t *testing.T) {
		hexStr, err := validatePluginSignedSlot(canonical, sign(canonical))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hexStr == "" {
			t.Fatal("expected non-empty signed hex")
		}
	})

	t.Run("signs a different txn -> rejected", func(t *testing.T) {
		other := canonical
		other.Amount++ // substitution
		if _, err := validatePluginSignedSlot(canonical, sign(other)); err == nil {
			t.Fatal("expected substitution to be rejected")
		}
	})

	t.Run("bad base64 -> error", func(t *testing.T) {
		if _, err := validatePluginSignedSlot(canonical, "!!!"); err == nil {
			t.Fatal("expected error for bad base64")
		}
	})

	t.Run("bad msgpack -> error", func(t *testing.T) {
		if _, err := validatePluginSignedSlot(canonical, base64.StdEncoding.EncodeToString([]byte("nope"))); err == nil {
			t.Fatal("expected error for bad msgpack")
		}
	})
}
