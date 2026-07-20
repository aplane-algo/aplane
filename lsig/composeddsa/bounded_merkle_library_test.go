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
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBundledBoundedMerkleAllowlistGolden(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.falcon1024-allowlist.v2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if spec.SchemaVersion != 2 || metadata == nil || len(metadata.DerivedArgs) != 1 || len(metadata.ArgumentLayout) != 2 {
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
	if gotFingerprint != "1:a1d103ee696878b348d443d49b8bc1bfede7c287d31bf218e6dede651c6b75ad" || gotHash != "bc92b273667a8a23205428a4150e9dc33acf0fd71cfba0ebb7a91c2bb0f0cbd3" {
		t.Errorf("goldens: fingerprint %q; TEAL SHA-256 %q", gotFingerprint, gotHash)
	}
}
