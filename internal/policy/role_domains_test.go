// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestRoleDomainsFixtureParsesAndRoundTrips(t *testing.T) {
	raw, err := os.ReadFile(roleDomainFixturePath(t))
	if err != nil {
		t.Fatalf("ReadFile(role fixture) error = %v", err)
	}
	stored, err := ParseStoredConfig(raw)
	if err != nil {
		t.Fatalf("ParseStoredConfig(role fixture) error = %v", err)
	}
	if stored.ClientSigning == nil {
		t.Fatal("ClientSigning = nil, want populated role block")
	}
	if stored.Attestation == nil {
		t.Fatal("Attestation = nil, want populated role block")
	}

	encoded, err := MarshalStoredConfig(stored)
	if err != nil {
		t.Fatalf("MarshalStoredConfig(role fixture) error = %v", err)
	}
	roundTrip, err := ParseStoredConfig(encoded)
	if err != nil {
		t.Fatalf("ParseStoredConfig(round trip) error = %v\nyaml:\n%s", err, encoded)
	}
	if roundTrip.ClientSigning == nil || roundTrip.Attestation == nil {
		t.Fatalf("round-tripped roles = client:%#v attestation:%#v", roundTrip.ClientSigning, roundTrip.Attestation)
	}
}

func TestStoredConfigApplyClientSigningRoleOverridesLegacyTopLevel(t *testing.T) {
	topReject := true
	clientReject := false
	stored := &StoredConfig{
		RejectForeignRekey: &topReject,
		ClientSigning: &StoredRoleConfig{
			RejectForeignRekey: &clientReject,
		},
	}

	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if cfg.RejectForeignRekey {
		t.Fatal("RejectForeignRekey = true, want client_signing override false")
	}
}

func TestStoredConfigApplyAttestationRole(t *testing.T) {
	rejectRekey := true
	enabled := true
	addr := types.Address{1}.String()
	stored := &StoredConfig{
		Attestation: &StoredRoleConfig{
			RejectRekey: &rejectRekey,
			TransferPolicy: &StoredTransferPolicy{
				SchemaVersion: 1,
				Enabled:       &enabled,
				Routes: []StoredTransferRoute{{
					ID:           "attestor_route",
					Networks:     []string{"testnet"},
					Sources:      []string{"*"},
					Assets:       []StoredAssetTerm{{Raw: "algo"}},
					Destinations: []string{addr},
				}},
			},
		},
	}

	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if cfg.Attestation == nil {
		t.Fatal("Attestation = nil, want effective attestation config")
	}
	if !cfg.Attestation.RejectRekey {
		t.Fatal("Attestation.RejectRekey = false, want true")
	}
	if cfg.Attestation.TransferPolicy == nil || cfg.Attestation.TransferPolicy.OnNoRoute != TransferOnNoRouteReject {
		t.Fatalf("Attestation.TransferPolicy = %#v, want implicit reject route miss", cfg.Attestation.TransferPolicy)
	}
}

func TestParseStoredConfigRejectsReviewProducingAttestationFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "always review warnings",
			raw: `
attestation:
  always_review_warnings: true
`,
			want: "attestation.always_review_warnings",
		},
		{
			name: "review algo payments",
			raw: `
attestation:
  review_algo_payments:
    testnet: 1
`,
			want: "attestation.review_algo_payments",
		},
		{
			name: "route miss review",
			raw: `
attestation:
  transfer_policy:
    schema_version: 1
    enabled: true
    on_no_route: review
`,
			want: "attestation.transfer_policy.on_no_route",
		},
		{
			name: "route review above",
			raw: `
attestation:
  transfer_policy:
    schema_version: 1
    enabled: true
    on_no_route: reject
    routes:
      - id: route
        networks: [testnet]
        sources: ["*"]
        assets: ["algo"]
        destinations: ["*"]
        limits:
          review_above: 10
`,
			want: "limits.review_above",
		},
		{
			name: "client reject rekey",
			raw: `
client_signing:
  reject_rekey: true
`,
			want: "client_signing.reject_rekey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStoredConfig([]byte(tt.raw))
			if err == nil {
				t.Fatal("ParseStoredConfig() error = nil, want role-domain rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseStoredConfig() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func roleDomainFixturePath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "test", "contracts", "policy", "role_domains_attestation.yaml")
}
