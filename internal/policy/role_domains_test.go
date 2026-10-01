// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
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
	if stored.RejectForeignRekey == nil || !*stored.RejectForeignRekey || stored.TransferPolicy == nil {
		t.Fatalf("fixture = %#v, want top-level client-signing fields", stored)
	}

	encoded, err := MarshalStoredConfig(stored)
	if err != nil {
		t.Fatalf("MarshalStoredConfig(role fixture) error = %v", err)
	}
	roundTrip, err := ParseStoredConfig(encoded)
	if err != nil {
		t.Fatalf("ParseStoredConfig(round trip) error = %v\nyaml:\n%s", err, encoded)
	}
	if roundTrip.RejectForeignRekey == nil || roundTrip.TransferPolicy == nil ||
		len(roundTrip.TransferPolicy.Routes) != 1 || roundTrip.TransferPolicy.Routes[0].ID != "client-mainnet-ops" {
		t.Fatalf("round-tripped fixture = %#v", roundTrip)
	}
}

func TestStoredConfigApplyCosignerRole(t *testing.T) {
	rejectRekey := true
	enabled := true
	addr := types.Address{1}.String()
	stored := &StoredConfig{StoredPolicyCore: StoredPolicyCore{RejectRekey: &rejectRekey, TransferPolicy: &StoredTransferPolicy{
		SchemaVersion: 1,
		Enabled:       &enabled,
		Routes: []StoredTransferRoute{{
			ID:           "cosigner_route",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{addr},
		}},
	}},
	}

	cfg, err := stored.ApplyCosigner(DefaultConfig())
	if err != nil {
		t.Fatalf("ApplyCosigner() error = %v", err)
	}
	if !cfg.RejectRekey {
		t.Fatal("RejectRekey = false, want true")
	}
	if cfg.TransferPolicy == nil || cfg.TransferPolicy.OnNoRoute != TransferOnNoRouteReject || cfg.TransferPolicy.CloseOnNoRoute != TransferOnNoRouteReject || cfg.TransferPolicy.ClawbackOnNoRoute != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy = %#v, want implicit reject route miss", cfg.TransferPolicy)
	}
}

func TestStoredConfigApplyCosignerRekeyPolicy(t *testing.T) {
	source := types.Address{90}
	target := types.Address{91}
	otherTarget := types.Address{92}
	stored, err := ParseStoredCosignerConfig([]byte(fmt.Sprintf(`
transfer_policy:
  schema_version: 1
  enabled: true
  address_sets:
    senders: [%q]
    targets: [%q]
  routes: []
rekey_policy:
  allowed:
    - sender: "@senders"
      targets: ["@targets"]
`, source.String(), target.String())))
	if err != nil {
		t.Fatalf("ParseStoredCosignerConfig() error = %v", err)
	}
	cfg, err := stored.ApplyCosigner(DefaultConfig())
	if err != nil {
		t.Fatalf("ApplyCosigner() error = %v", err)
	}
	if cfg.RekeyPolicy == nil {
		t.Fatal("RekeyPolicy = nil")
	}
	if !cfg.RekeyPolicy.Allows(source, target) {
		t.Fatal("RekeyPolicy did not allow configured sender -> target")
	}
	if cfg.RekeyPolicy.Allows(source, otherTarget) {
		t.Fatal("RekeyPolicy allowed unconfigured target")
	}
}

func TestParseStoredConfigRejectsCosignerPolicyFields(t *testing.T) {
	for _, raw := range []string{
		"client_signing: {}\n",
		"cosigner: {}\n",
		"reject_rekey: true\n",
		"rekey_policy: {}\n",
	} {
		_, err := ParseStoredConfig([]byte(raw))
		if err == nil {
			t.Fatalf("ParseStoredConfig(%q) error = nil, want signing document rejection", raw)
		}
	}
}

func TestParseStoredCosignerConfigRejectsReviewProducingFields(t *testing.T) {
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
			want: "cosigner.always_review_warnings",
		},
		{
			name: "review algo payments",
			raw: `
review_algo_payments:
  testnet: 1
`,
			want: "cosigner.review_algo_payments",
		},
		{
			name: "route miss review",
			raw: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: review
`,
			want: "cosigner.transfer_policy.on_no_route",
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
cosigner: {}
`,
			want: "must not contain a cosigner wrapper",
		},
		{
			name: "client signing block",
			raw: `
client_signing: {}
`,
			want: `unknown policy field "client_signing"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStoredCosignerConfig([]byte(tt.raw))
			if err == nil {
				t.Fatal("ParseStoredCosignerConfig() error = nil, want role-domain rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseStoredCosignerConfig() error = %v, want containing %q", err, tt.want)
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
	return filepath.Join(filepath.Dir(file), "..", "..", "test", "contracts", "policy", "role_domains_signer.yaml")
}
