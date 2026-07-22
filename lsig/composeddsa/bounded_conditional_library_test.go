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
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBundledBoundedConditionalGoldens(t *testing.T) {
	falcon1024.RegisterClient()
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	tests := []struct {
		name            string
		parameters      map[string]string
		wantRuntimeArgs int
		wantFingerprint string
		wantTEALSHA256  string
	}{
		{
			name:            "aplane.falcon1024-timelock.v1.yaml",
			parameters:      map[string]string{"unlock_round": "50000000"},
			wantFingerprint: "1:23324e4edb95ba0c8cd7c398e4c9641b00ac5240e826a78dd4c4a40fdf21d851",
			wantTEALSHA256:  "ba093fba6122367d99b6159b792733ec881ca0774ef63e6d2adcc11749391529",
		},
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
			if spec.SchemaVersion != 2 || metadata == nil || metadata.Layer3Policy != boundedmeta.Layer3PolicyCustom || len(metadata.RuntimeArgs) != test.wantRuntimeArgs {
				t.Fatalf("bounded conditional metadata = %#v", metadata)
			}
			if len(metadata.AdminOperations) != 1 || metadata.AdminOperations[0].PolicyGate != boundedmeta.PolicyGateLayer3 {
				t.Fatalf("bounded conditional rekey operation = %#v", metadata.AdminOperations)
			}
			teal, err := provider.GenerateTEAL(publicKey, test.parameters)
			if err != nil {
				t.Fatal(err)
			}
			rekeyStart := strings.Index(teal, "__aplane_bounded1_rekey:")
			spendStart := strings.Index(teal, "__aplane_bounded1_spend:")
			if rekeyStart < 0 || spendStart <= rekeyStart || !strings.Contains(teal[rekeyStart:spendStart], "b __aplane_bounded1_spend") {
				t.Fatalf("pure rekey does not pass through Layer 3:\n%s", teal)
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
