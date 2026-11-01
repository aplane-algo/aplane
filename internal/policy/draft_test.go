// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// draftFixtureKey is the key a fixture is decoded for: its own key field, as
// the schema fixture test does.
func draftFixtureKey(data []byte) string {
	var head struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(data, &head)
	return head.Key
}

// TestDraftCanonicalFormOfFixtures checks every contract fixture: a document
// that parses formats idempotently, and its canonical form decodes to the same
// document, or fails with the same error, as the original.
func TestDraftCanonicalFormOfFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "contracts", "policy", "v1")
	// The valid fixtures are already canonical, except this one, which puts
	// limits after transfer_policy.
	reordered := map[string]bool{"signer_uint64_max.json": true}
	parsed := 0
	for _, pattern := range []string{"*.json", filepath.Join("invalid", "*.json"), filepath.Join("semantic_invalid", "*.json")} {
		files, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil || len(files) == 0 {
			t.Fatalf("no fixtures matched %s: %v", pattern, err)
		}
		for _, file := range files {
			name := filepath.ToSlash(file[len(dir)+1:])
			t.Run(name, func(t *testing.T) {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				draft, err := ParseDraft(data)
				if err != nil {
					if _, decodeErr := DecodePolicyV1(data, draftFixtureKey(data), fixtureRole(t, file)); decodeErr == nil || decodeErr.Error() != err.Error() {
						t.Fatalf("ParseDraft error %v, but the decoder says %v", err, decodeErr)
					}
					return
				}
				parsed++
				canonical, err := draft.Canonical()
				if err != nil {
					t.Fatal(err)
				}
				again, err := ParseDraft(canonical)
				if err != nil {
					t.Fatalf("canonical form does not parse: %v", err)
				}
				if second, err := again.Canonical(); err != nil || !bytes.Equal(second, canonical) {
					t.Fatalf("formatting is not idempotent (err %v)", err)
				}
				if !strings.Contains(name, "/") && !reordered[name] && !bytes.Equal(canonical, data) {
					t.Errorf("valid fixture is not already canonical:\n%s", canonical)
				}

				role := fixtureRole(t, file)
				key := draftFixtureKey(data)
				want, wantErr := DecodePolicyV1(data, key, role)
				got, gotErr := DecodePolicyV1(canonical, key, role)
				if (wantErr == nil) != (gotErr == nil) || (wantErr != nil && wantErr.Error() != gotErr.Error()) {
					t.Fatalf("decode error changed: %v -> %v", wantErr, gotErr)
				}
				if !reflect.DeepEqual(want, got) {
					t.Fatalf("decoded document changed")
				}
			})
		}
	}
	if parsed == 0 {
		t.Fatal("no fixture parsed as a draft")
	}
}

func TestDraftKeepsWhatAnInvalidDocumentHolds(t *testing.T) {
	input := `{"zz_unknown": {"b": 1, "a": 2}, "role": "signer", "format": "aplane.policy.v1",
		"max_fee_microalgos": 1.50e3, "transaction_types": {"pay": "allow", "*": "reject"},
		"transfer_policy": {"routes": [{"sources": ["x"], "id": "r", "extra": null}], "on_no_route": 7},
		"description": "<a & b>"}`
	draft, err := ParseDraft([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	got, err := draft.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "format": "aplane.policy.v1",
  "role": "signer",
  "description": "<a & b>",
  "max_fee_microalgos": 1.50e3,
  "transaction_types": {
    "pay": "allow",
    "*": "reject"
  },
  "transfer_policy": {
    "on_no_route": 7,
    "routes": [
      {
        "id": "r",
        "sources": [
          "x"
        ],
        "extra": null
      }
    ]
  },
  "zz_unknown": {
    "b": 1,
    "a": 2
  }
}
`
	if string(got) != want {
		t.Fatalf("canonical form:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseDraftRejectsWhatTheDecoderRejects(t *testing.T) {
	for name, input := range map[string]string{
		"duplicate key": `{"format": "a", "format": "b"}`,
		"trailing data": `{} {}`,
		"truncated":     `{"format": "aplane.policy.v1",`,
		"comment":       "{\"format\": \"aplane.policy.v1\" // note\n}",
		"invalid UTF-8": "{\"description\": \"\xff\"}",
		"too deep":      strings.Repeat("[", maxPolicyDocumentDepth+2) + strings.Repeat("]", maxPolicyDocumentDepth+2),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDraft([]byte(input)); err == nil {
				t.Fatal("ParseDraft accepted input the decoder rejects")
			}
		})
	}
}

func TestDraftCanonicalRefusesOutputOverTheLimit(t *testing.T) {
	// Compact input under the limit whose indented form is over it.
	items := strings.TrimSuffix(strings.Repeat(`"a",`, 200_000), ",")
	input := []byte(`{"x":[` + items + `]}`)
	if len(input) > maxPolicyDocumentBytes {
		t.Fatalf("test input is %d bytes, over the limit", len(input))
	}
	draft, err := ParseDraft(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := draft.Canonical(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("Canonical() error = %v, want a size-limit refusal", err)
	}
}

// TestCanonicalFieldOrderMatchesSchema keeps canonicalFieldOrder in step with
// the published schema: each policy object's field list holds exactly the
// fields the schema allows on it, across both roles. A field added to the
// format without a place in the canonical order fails here.
func TestCanonicalFieldOrderMatchesSchema(t *testing.T) {
	var schema struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(policyschema.SchemaV1, &schema); err != nil {
		t.Fatal(err)
	}
	props := func(path ...string) []string {
		t.Helper()
		var node any
		if err := json.Unmarshal(schema.Defs[path[0]], &node); err != nil {
			t.Fatalf("$defs/%s: %v", path[0], err)
		}
		for _, step := range path[1:] {
			m, ok := node.(map[string]any)
			if !ok {
				t.Fatalf("schema path %v: %q is not an object", path, step)
			}
			node = m[step]
		}
		m, _ := node.(map[string]any)
		var names []string
		for name := range m {
			names = append(names, name)
		}
		return names
	}
	union := func(lists ...[]string) []string {
		var out []string
		for _, list := range lists {
			for _, name := range list {
				if !slices.Contains(out, name) {
					out = append(out, name)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	for _, tt := range []struct {
		ctx  canonicalContext
		want []string
	}{
		{ctxRoot, union(props("signerPolicy", "properties"), props("cosignerPolicy", "properties"))},
		{ctxTransferPolicy, union(props("signerTransferPolicy", "properties"), props("cosignerTransferPolicy", "properties"))},
		{ctxRoute, union(props("routeShape", "properties"), props("signerRoute", "properties"), props("cosignerRoute", "properties"))},
		{ctxThresholds, union(
			props("signerLimits", "additionalProperties", "additionalProperties", "properties"),
			props("cosignerLimits", "additionalProperties", "additionalProperties", "properties"))},
		{ctxRekeyPolicy, union(props("rekeyPolicy", "properties"))},
		{ctxRekeyRule, union(props("rekeyPolicy", "properties", "allowed", "items", "properties"))},
	} {
		got := union(canonicalFieldOrder[tt.ctx])
		if len(tt.want) == 0 || !slices.Equal(got, tt.want) {
			t.Errorf("context %d: canonical fields %v, schema fields %v", tt.ctx, got, tt.want)
		}
	}
}

// TestCanonicalOrderWithEveryField pins the order of every policy object's
// fields, using a document (signer and cosigner fields together) whose members
// are all present and listed in reverse. Canonical output is meant to stay
// byte-stable across releases, so a change to the order must be deliberate.
func TestCanonicalOrderWithEveryField(t *testing.T) {
	reversed := func(ctx canonicalContext, value func(string) string) string {
		order := canonicalFieldOrder[ctx]
		parts := make([]string, 0, len(order))
		for i := len(order) - 1; i >= 0; i-- {
			parts = append(parts, `"`+order[i]+`": `+value(order[i]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	scalar := func(string) string { return "0" }
	thresholds := reversed(ctxThresholds, scalar)
	limits := `{"mainnet": {"algo": ` + thresholds + `}}`
	route := reversed(ctxRoute, func(f string) string {
		if f == "limits" {
			return limits
		}
		return "0"
	})
	tp := reversed(ctxTransferPolicy, func(f string) string {
		if f == "routes" {
			return "[" + route + "]"
		}
		return "0"
	})
	rekey := reversed(ctxRekeyPolicy, func(string) string { return "[" + reversed(ctxRekeyRule, scalar) + "]" })
	root := reversed(ctxRoot, func(f string) string {
		switch f {
		case "limits":
			return limits
		case "transfer_policy":
			return tp
		case "rekey_policy":
			return rekey
		}
		return "0"
	})
	draft, err := ParseDraft([]byte(root))
	if err != nil {
		t.Fatal(err)
	}
	out, err := draft.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, `": `); i > 0 {
			keys = append(keys, strings.TrimLeft(line[:i], ` "`))
		}
	}
	want := `format role key description reject_foreign_rekey reject_close_remainder reject_asset_close ` +
		`reject_clawback reject_rekey always_review_warnings auto_approve_self_noop_transfer max_fee_microalgos ` +
		`transaction_types limits mainnet algo review_above reject_above address_sets asset_sets ` +
		`transfer_policy on_no_route close_on_no_route clawback_on_no_route blocked_destinations routes ` +
		`id description networks sources assets destinations asset_sources ` +
		`limits mainnet algo review_above reject_above allow_close allow_clawback ` +
		`rekey_policy allowed sender targets`
	if got := strings.Join(keys, " "); got != want {
		t.Fatalf("canonical key order:\n%s\nwant:\n%s", got, want)
	}
}
