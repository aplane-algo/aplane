// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBundledCorridorV1Contract(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.corridor.v1.yaml")
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
	if provider.KeyType() != "aplane.corridor.v1" || provider.Layer3PolicyName() != boundedmeta.Layer3PolicyMerkleAllowlist {
		t.Fatalf("Corridor provider = %q policy %q", provider.KeyType(), provider.Layer3PolicyName())
	}

	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Contract != boundedmeta.ContractV1 || metadata.Cosigner == nil || metadata.Cosigner.Contract != boundedmeta.CosignerContractV1 {
		t.Fatalf("Corridor metadata = %#v", metadata)
	}
	if metadata.Layer3Policy != boundedmeta.Layer3PolicyMerkleAllowlist || len(metadata.DerivedArgs) != 1 || len(metadata.ArgumentLayout) != 4 {
		t.Fatalf("Corridor metadata shape = %#v", metadata)
	}
	wantSlots := []struct{ name, source string }{
		{"base_signature_0", boundedmeta.ArgSourceBaseSignature},
		{"merkle_proof", boundedmeta.ArgSourceDerived},
		{boundedmeta.CosignerSignatureSlot, boundedmeta.ArgSourceCosigner},
		{"admin_signature", boundedmeta.ArgSourceAdmin},
	}
	for i, want := range wantSlots {
		slot := metadata.ArgumentLayout[i]
		if slot.Index != i || slot.Name != want.name || slot.Source != want.source {
			t.Fatalf("Corridor argument slot %d = %#v, want %q/%q", i, slot, want.name, want.source)
		}
	}

	params := map[string]string{
		"recipients":               types.Address{1}.String(),
		"cosigner_public_key":      hex.EncodeToString(bytes.Repeat([]byte{0x22}, falconfamily.PublicKeySize)),
		"bounded_admin_public_key": hex.EncodeToString(bytes.Repeat([]byte{0x33}, boundedmeta.FalconAdminPublicKeySize)),
	}
	if err := provider.ValidateCreationParams(params); err != nil {
		t.Fatal(err)
	}
	teal, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x11}, falconfamily.PublicKeySize), params)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"framework-owned Merkle allowlist",
		"arg 1\nlen\npushint 512",
		"arg 2",
		"Contract-admin-authorized pure rekey",
	} {
		if !strings.Contains(teal, fragment) {
			t.Errorf("Corridor TEAL missing %q", fragment)
		}
	}
	hash := sha256.Sum256([]byte(teal))
	gotHash := hex.EncodeToString(hash[:])
	gotFingerprint := provider.CompatibilityFingerprint()
	if gotFingerprint != "1:f24a1b55bf4939ade58058063f207bf1e818c06f16a1ba0aaffbd75fc84fbbda" || gotHash != "c21019a9a4840dc695085e84aaeba1566159c036bf37660cf22c8b53b01feb10" {
		t.Fatalf("Corridor goldens: fingerprint %q; TEAL SHA-256 %q", gotFingerprint, gotHash)
	}
}
