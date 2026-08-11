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

func TestBundledBoundedInlineAllowlistGoldens(t *testing.T) {
	falcon1024.RegisterClient()
	recipient := types.Address{1}.String()
	tests := []struct {
		name            string
		publicKey       []byte
		wantFingerprint string
		wantTEALSHA256  string
	}{
		{name: "aplane.falcon1024-allowlist.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), wantFingerprint: "1:527d9beb4a92723347a14258225fb2cd3024b1aa63d878c4b7d69467e99fcd59", wantTEALSHA256: "b08fa7a01a034c6e2a73597b5d42e006cc668c62869bec9daaa73fee0dccf4b0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := templates.ReadFile(test.name)
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
			if spec.SchemaVersion != 2 || metadata == nil || metadata.Contract != boundedmeta.ContractV1 || metadata.MaxFee != 10_000 || metadata.Layer3Policy != boundedmeta.Layer3PolicyFixedAllowlist || len(metadata.ArgumentLayout) != 1 {
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
