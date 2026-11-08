// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// A custom Layer 3 policy is author TEAL, and a rekey never reaches it. The
// timelock fixture therefore refuses rekeys, and its program has no rekey path.
func TestBoundedConditionalGoldens(t *testing.T) {
	falcon1024.RegisterClient()
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	tests := []struct {
		name            string
		yaml            string
		parameters      map[string]string
		wantRuntimeArgs int
		wantFingerprint string
		wantTEALSHA256  string
	}{
		{
			name:            "custom timelock",
			yaml:            composeddsa.CustomTimelockFixtureYAML,
			parameters:      map[string]string{"unlock_round": "50000000"},
			wantFingerprint: "1:ac54c2e2172eb70b68ee356cd2fa3bb10d3b5eb3715da6e0d6033a0138c273e5",
			wantTEALSHA256:  "5e66cac49318633d85ddf52cc4f97ef7127f3d4fae339d25d01256658a2429fc",
		},
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
			if spec.SchemaVersion != 2 || metadata == nil || metadata.Layer3Policy != boundedmeta.Layer3PolicyCustom || len(metadata.RuntimeArgs) != test.wantRuntimeArgs {
				t.Fatalf("bounded conditional metadata = %#v", metadata)
			}
			if metadata.Rekey != boundedmeta.RekeyRefused {
				t.Fatalf("bounded conditional rekey = %q, want %q", metadata.Rekey, boundedmeta.RekeyRefused)
			}
			teal, err := provider.GenerateTEAL(publicKey, test.parameters)
			if err != nil {
				t.Fatal(err)
			}
			rekeyStart := strings.Index(teal, "__aplane_bounded1_rekey:")
			spendStart := strings.Index(teal, "__aplane_bounded1_spend:")
			if rekeyStart < 0 || spendStart <= rekeyStart || teal[rekeyStart:spendStart] != "__aplane_bounded1_rekey:\nerr\n\n" {
				t.Fatalf("a refused rekey does not fail closed before Layer 3:\n%s", teal)
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
