// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policytest builds complete policy documents for tests. Every
// verdict-bearing field of a document is required, so a test that cares about
// one field merges a sparse JSON object onto a complete minimal document
// instead of writing the whole thing.
package policytest

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// Minimal returns the complete minimal document map for role and key. A
// signer document rejects foreign rekeys, allows every type, and rejects
// every route miss; a cosigner document allows pay and axfer with no routes.
func Minimal(role noderole.Role, key string) map[string]any {
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

// Document returns a complete, indented document for role and key with the
// members of sparse (a JSON object, or "") merged in. transfer_policy merges
// one level deep, so a route list can be given without the route-miss
// actions.
func Document(role noderole.Role, key, sparse string) (string, error) {
	base := Minimal(role, key)
	if sparse != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(sparse), &extra); err != nil {
			return "", fmt.Errorf("sparse policy fragment is not a JSON object: %w\n%s", err, sparse)
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
		return "", err
	}
	return string(out) + "\n", nil
}

// MustDocument is Document for package-level test fixtures; it panics on a
// malformed fragment.
func MustDocument(role noderole.Role, key, sparse string) string {
	doc, err := Document(role, key, sparse)
	if err != nil {
		panic(err)
	}
	return doc
}

// Signer returns a complete signer document.
func Signer(t testing.TB, key, sparse string) string {
	t.Helper()
	doc, err := Document(noderole.RoleSigner, key, sparse)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// Cosigner returns a complete cosigner document.
func Cosigner(t testing.TB, key, sparse string) string {
	t.Helper()
	doc, err := Document(noderole.RoleCosigner, key, sparse)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// Compile decodes and compiles a complete document for role and key with
// sparse merged in.
func Compile(t testing.TB, role noderole.Role, key, sparse string) *policy.Config {
	t.Helper()
	doc, err := Document(role, key, sparse)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policy.DecodePolicyV1([]byte(doc), key, role)
	if err != nil {
		t.Fatalf("DecodePolicyV1(%s) error = %v\n%s", role, err, doc)
	}
	cfg, err := decoded.Compile(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return cfg
}

// AllowAllTypes is the transaction_types map a hand-built Config needs to
// leave every type to the other rules.
func AllowAllTypes() policy.TransactionTypesV1 {
	return policy.TransactionTypesV1{policy.TransactionTypeWildcard: policy.TransactionTypeAllow}
}

// EmbeddedDefault returns the shipped default for role as a string.
func EmbeddedDefault(t testing.TB, role noderole.Role) string {
	t.Helper()
	data, err := policy.EmbeddedDefault(role)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
