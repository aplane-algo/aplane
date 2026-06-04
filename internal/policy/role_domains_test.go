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

	encoded, err := MarshalStoredConfig(stored)
	if err != nil {
		t.Fatalf("MarshalStoredConfig(role fixture) error = %v", err)
	}
	roundTrip, err := ParseStoredConfig(encoded)
	if err != nil {
		t.Fatalf("ParseStoredConfig(round trip) error = %v\nyaml:\n%s", err, encoded)
	}
	if roundTrip.ClientSigning == nil {
		t.Fatalf("round-tripped client role = %#v", roundTrip.ClientSigning)
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
	}

	cfg, err := stored.ApplyAttestation(DefaultConfig())
	if err != nil {
		t.Fatalf("ApplyAttestation() error = %v", err)
	}
	if !cfg.RejectRekey {
		t.Fatal("RejectRekey = false, want true")
	}
	if cfg.TransferPolicy == nil || cfg.TransferPolicy.OnNoRoute != TransferOnNoRouteReject || cfg.TransferPolicy.CloseOnNoRoute != TransferOnNoRouteReject || cfg.TransferPolicy.ClawbackOnNoRoute != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy = %#v, want implicit reject route miss", cfg.TransferPolicy)
	}
}

func TestParseStoredConfigRejectsAttestationPolicyFields(t *testing.T) {
	for _, raw := range []string{
		"attestation: {}\n",
		"reject_rekey: true\n",
	} {
		_, err := ParseStoredConfig([]byte(raw))
		if err == nil {
			t.Fatalf("ParseStoredConfig(%q) error = nil, want signing document rejection", raw)
		}
	}
}

func TestParseStoredAttestationConfigRejectsReviewProducingFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "always review warnings",
			raw: `
always_review_warnings: true
`,
			want: "attestation.always_review_warnings",
		},
		{
			name: "review algo payments",
			raw: `
review_algo_payments:
  testnet: 1
`,
			want: "attestation.review_algo_payments",
		},
		{
			name: "route miss review",
			raw: `
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
			name: "wrapper",
			raw: `
attestation: {}
`,
			want: "attestation.yaml must not contain an attestation wrapper",
		},
		{
			name: "client reject rekey",
			raw: `
client_signing: {}
`,
			want: "attestation.yaml client_signing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStoredAttestationConfig([]byte(tt.raw))
			if err == nil {
				t.Fatal("ParseStoredAttestationConfig() error = nil, want role-domain rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseStoredAttestationConfig() error = %v, want containing %q", err, tt.want)
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
