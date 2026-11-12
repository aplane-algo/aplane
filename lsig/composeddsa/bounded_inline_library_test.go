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

func TestBoundedInlineAllowlistGoldens(t *testing.T) {
	falcon1024.RegisterClient()
	recipient := types.Address{1}.String()
	tests := []struct {
		name            string
		yaml            string
		publicKey       []byte
		wantFingerprint string
		wantTEALSHA256  string
	}{
		{name: "fixed allowlist", yaml: composeddsa.FixedAllowlistFixtureYAML, publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), wantFingerprint: "1:e759c9f14b13908c720c94216abbb61bcb2c2ed2227ebc30eb6ff75847b85d87", wantTEALSHA256: "f848a80eaf26dd0844f67ac4a345e4b0ff23f1709e6017ffe1677cd704c61b51"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, err := composeddsa.ParseTemplateSpec([]byte(test.yaml))
			if err != nil {
				t.Fatal(err)
			}
			provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			metadata := provider.BoundedAuthorizationMetadata()
			if spec.SchemaVersion != 2 || metadata == nil || metadata.Contract != boundedmeta.Contract || metadata.Rekey != boundedmeta.RekeySpendingKey || metadata.MaxFee == nil || *metadata.MaxFee != 10_000 || metadata.Layer3Policy != boundedmeta.Layer3PolicyFixedAllowlist || len(metadata.ArgumentLayout) != 1 {
				t.Fatalf("bounded inline metadata = %#v", metadata)
			}
			teal, err := provider.GenerateTEAL(test.publicKey, map[string]string{"recipients": recipient})
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte(teal))
			gotHash := hex.EncodeToString(hash[:])
			gotFingerprint := provider.CompatibilityFingerprint()
			if gotFingerprint != test.wantFingerprint || gotHash != test.wantTEALSHA256 {
				t.Errorf("goldens: fingerprint %q; TEAL SHA-256 %q", gotFingerprint, gotHash)
			}
		})
	}
}
