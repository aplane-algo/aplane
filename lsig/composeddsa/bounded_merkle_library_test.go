// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBoundedMerkleAllowlistGolden(t *testing.T) {
	falcon1024.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(composeddsa.MerkleAllowlistFixtureYAML))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if spec.SchemaVersion != 2 || metadata == nil || metadata.Rekey != boundedmeta.RekeySpendingKey || len(metadata.DerivedArgs) != 1 || len(metadata.ArgumentLayout) != 2 {
		t.Fatalf("bounded Merkle metadata = %#v", metadata)
	}
	slot := metadata.ArgumentLayout[1]
	if slot.Name != "merkle_proof" || slot.Source != boundedmeta.ArgSourceDerived || slot.MaxSize != boundedmeta.MerkleProofSize || slot.Paths.Spend != boundedmeta.ArgOptional || slot.Paths.SpendingRekey != boundedmeta.ArgForbidden {
		t.Fatalf("bounded Merkle proof slot = %#v", slot)
	}
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	teal, err := provider.GenerateTEAL(publicKey, map[string]string{"recipients": types.Address{1}.String()})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(teal))
	gotHash := hex.EncodeToString(hash[:])
	gotFingerprint := provider.CompatibilityFingerprint()
	if gotFingerprint != "1:dd1836989fdf67daaa5ae012dfae85738cc76d2eab8259e3a01220b0dd853f0f" || gotHash != "54f477a2a1c161f3680731c8dcfabaa26ed514e7a21486019073df182ee8553c" {
		t.Errorf("goldens: fingerprint %q; TEAL SHA-256 %q", gotFingerprint, gotHash)
	}
}
