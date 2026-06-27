// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// mixedSlots builds a grouped pair: one plugin-signed passthrough slot + one
// unsigned managed slot, both carrying the same group ID.
func mixedSlots(t *testing.T) []PregroupedMixedSlot {
	t.Helper()
	plugin := crypto.GenerateAccount()
	managed := crypto.GenerateAccount()
	pTxn := presignTestTxn(t, plugin.Address.String(), "plugin")
	mTxn := presignTestTxn(t, managed.Address.String(), "managed")
	gid, err := crypto.ComputeGroupID([]types.Transaction{pTxn, mTxn})
	if err != nil {
		t.Fatalf("group id: %v", err)
	}
	pTxn.Group, mTxn.Group = gid, gid
	_, pSigned, err := crypto.SignTransaction(plugin.PrivateKey, pTxn)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return []PregroupedMixedSlot{
		{Managed: false, Txn: pTxn, SignedRaw: pSigned},
		{Managed: true, Txn: mTxn},
	}
}

func TestValidatePregroupedMixed(t *testing.T) {
	t.Run("valid mixed group passes", func(t *testing.T) {
		if err := validatePregroupedMixed(mixedSlots(t)); err != nil {
			t.Fatalf("valid group rejected: %v", err)
		}
	})

	t.Run("single slot rejects", func(t *testing.T) {
		if err := validatePregroupedMixed(mixedSlots(t)[:1]); err == nil {
			t.Fatal("want error for single-slot group")
		}
	})

	t.Run("no managed slot rejects", func(t *testing.T) {
		slots := mixedSlots(t)
		// Flip the managed slot to a (well-formed) passthrough so the only failing
		// condition is the absence of a managed slot.
		slots[1].Managed = false
		slots[1].SignedRaw = slots[0].SignedRaw // any non-empty bytes
		if err := validatePregroupedMixed(slots); err == nil {
			t.Fatal("want error when no managed slot present")
		}
	})

	t.Run("no passthrough slot rejects", func(t *testing.T) {
		slots := mixedSlots(t)
		// Flip the passthrough slot to managed -> all-managed group, no passthrough.
		slots[0].Managed = true
		slots[0].SignedRaw = nil
		if err := validatePregroupedMixed(slots); err == nil {
			t.Fatal("want error when no plugin-signed passthrough slot present")
		}
	})

	t.Run("passthrough without signed bytes rejects", func(t *testing.T) {
		slots := mixedSlots(t)
		slots[0].SignedRaw = nil
		if err := validatePregroupedMixed(slots); err == nil {
			t.Fatal("want error for passthrough slot with no signed bytes")
		}
	})

	t.Run("mismatched group ids reject", func(t *testing.T) {
		slots := mixedSlots(t)
		slots[1].Txn.Group[0] ^= 0xFF
		if err := validatePregroupedMixed(slots); err == nil {
			t.Fatal("want error when group ids differ")
		}
	})

	t.Run("tampered member (stale group id) rejects", func(t *testing.T) {
		slots := mixedSlots(t)
		slots[1].Txn.Amount++ // recomputed group id no longer matches
		if err := validatePregroupedMixed(slots); err == nil {
			t.Fatal("want error for tampered member")
		}
	})

	t.Run("missing group id rejects", func(t *testing.T) {
		slots := mixedSlots(t)
		slots[0].Txn.Group = types.Digest{}
		if err := validatePregroupedMixed(slots); err == nil {
			t.Fatal("want error when a slot has no group id")
		}
	})
}

func TestSignerLsigSize(t *testing.T) {
	eng, err := NewEngine("localnet")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	eng.SignerCache.LsigSizes["FALCON"] = 4000

	if got := eng.signerLsigSize("FALCON"); got != 4000 {
		t.Fatalf("falcon lsig size = %d, want 4000", got)
	}
	if got := eng.signerLsigSize("ED25519"); got != 0 { // not in cache -> ed25519/no budget
		t.Fatalf("ed25519 lsig size = %d, want 0", got)
	}
}
