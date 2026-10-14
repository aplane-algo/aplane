// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
)

// Every verdict-bearing field of a policy document is required, so tests
// that care about one field build their document by merging a sparse JSON
// object onto a complete minimal one. transfer_policy merges one level deep,
// so a test can name a route list without restating the route-miss actions.

func minimalPolicyMap(role noderole.Role, key string) map[string]any {
	base := map[string]any{
		"format":                 "aplane.policy.v1",
		"role":                   string(role),
		"key":                    key,
		"reject_close_remainder": false,
		"reject_asset_close":     false,
		"reject_clawback":        false,
		"max_fee_microalgos":     "0",
	}
	if role == noderole.RoleCosigner {
		base["reject_rekey"] = false
		base["transaction_types"] = map[string]any{"*": "reject", "pay": "allow", "axfer": "allow"}
		base["transfer_policy"] = map[string]any{"routes": []any{}}
		return base
	}
	base["reject_foreign_rekey"] = true
	base["always_review_warnings"] = false
	base["auto_approve_self_noop_transfer"] = false
	base["transaction_types"] = map[string]any{"*": "allow"}
	base["transfer_policy"] = map[string]any{
		"on_no_route": "reject", "close_on_no_route": "reject", "clawback_on_no_route": "reject", "routes": []any{},
	}
	return base
}

// completePolicyJSON returns a complete document for role and key with the
// members of sparse (a JSON object) merged in.
func completePolicyJSON(t *testing.T, role noderole.Role, key, sparse string) []byte {
	t.Helper()
	base := minimalPolicyMap(role, key)
	if sparse != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(sparse), &extra); err != nil {
			t.Fatalf("sparse policy fragment is not a JSON object: %v\n%s", err, sparse)
		}
		for k, v := range extra {
			if k == "transfer_policy" {
				tp, _ := base["transfer_policy"].(map[string]any)
				if nested, ok := v.(map[string]any); ok {
					for nk, nv := range nested {
						tp[nk] = nv
					}
					continue
				}
			}
			base[k] = v
		}
	}
	out, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func signerJSON(t *testing.T, key, sparse string) []byte {
	t.Helper()
	return completePolicyJSON(t, noderole.RoleSigner, key, sparse)
}

func cosignerJSON(t *testing.T, key, sparse string) []byte {
	t.Helper()
	return completePolicyJSON(t, noderole.RoleCosigner, key, sparse)
}

func mustSignerDoc(t *testing.T, key, sparse string) *PolicyV1 {
	t.Helper()
	doc, err := DecodePolicyV1(signerJSON(t, key, sparse), key, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("DecodePolicyV1(signer) error = %v\n%s", err, sparse)
	}
	return doc
}

func mustCosignerDoc(t *testing.T, key, sparse string) *PolicyV1 {
	t.Helper()
	doc, err := DecodePolicyV1(cosignerJSON(t, key, sparse), key, noderole.RoleCosigner)
	if err != nil {
		t.Fatalf("DecodePolicyV1(cosigner) error = %v\n%s", err, sparse)
	}
	return doc
}

// routingConfig compiles a signer default document with sparse merged in.
func routingConfig(t *testing.T, sparse string) *Config {
	t.Helper()
	cfg, err := mustSignerDoc(t, DefaultKey, sparse).Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return cfg
}

// allowAllTypes is the transaction_types map a hand-built Config needs to
// leave every type to the other rules.
func allowAllTypes() TransactionTypesV1 {
	return TransactionTypesV1{TransactionTypeWildcard: TransactionTypeAllow}
}
