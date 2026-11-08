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
	want := `format role key description rekeys reject_close_remainder reject_asset_close ` +
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

// TestDraftNodeWalkAndPointers walks every value of every parsable fixture and
// checks that At, given a node's pointer, returns that node.
func TestDraftNodeWalkAndPointers(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "contracts", "policy", "v1")
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	more, _ := filepath.Glob(filepath.Join(dir, "semantic_invalid", "*.json"))
	files = append(files, more...)
	walked := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		draft, err := ParseDraft(data)
		if err != nil {
			t.Fatal(err)
		}
		var walk func(n DraftNode)
		walk = func(n DraftNode) {
			walked++
			if got := draft.At(n.Pointer()); got.Pointer() != n.Pointer() || got.Kind() != n.Kind() || got.Text() != n.Text() {
				t.Fatalf("%s: At(%q) = %q %s, want the node itself", file, n.Pointer(), got.Pointer(), got.Kind())
			}
			for _, k := range n.Keys() {
				walk(n.Member(k))
			}
			for _, item := range n.Items() {
				walk(item)
			}
		}
		walk(draft.Root())
	}
	if walked < 100 {
		t.Fatalf("walked only %d nodes", walked)
	}
}

func TestDraftNodeAccessorsAndAbsentValues(t *testing.T) {
	draft, err := ParseDraft([]byte(`{"a/b": {"~x": [true, 1.50, "s", null]}, "n": 7}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := draft.At("/a~1b/~0x/1"); got.Kind() != "number" || got.Text() != "1.50" {
		t.Fatalf("escaped pointer: %s %q", got.Kind(), got.Text())
	}
	if got := draft.At("/a~1b/~0x/0"); got.Kind() != "boolean" || !got.Bool() {
		t.Fatalf("boolean: %s %v", got.Kind(), got.Bool())
	}
	if got := draft.At("/a~1b/~0x/3"); got.Kind() != "null" || !got.Exists() {
		t.Fatal("null item is not an existing null")
	}
	if keys := draft.Root().Keys(); len(keys) != 2 || keys[0] != "a/b" || keys[1] != "n" {
		t.Fatalf("keys = %v", keys)
	}
	for _, missing := range []string{"/missing", "/n/0", "/a~1b/~0x/4", "/a~1b/~0x/01", "/a~1b/~0x/-1", "x"} {
		if got := draft.At(missing); got.Exists() || got.Kind() != "" || got.Keys() != nil || got.Items() != nil || got.Member("k").Exists() {
			t.Fatalf("At(%q) = %s, want an absent node", missing, got.Kind())
		}
	}
}

func mustCanonical(t *testing.T, d *Draft) string {
	t.Helper()
	out, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(out)), " ")
}

func TestDraftEditsReturnNewDraftsWithFreshPointers(t *testing.T) {
	base, err := ParseDraft([]byte(`{"a": 1, "list": ["x", "y"], "obj": {"k": true}}`))
	if err != nil {
		t.Fatal(err)
	}
	before := mustCanonical(t, base)
	for _, tt := range []struct {
		name string
		edit func(*Draft) (*Draft, error)
		want string
	}{
		{"set existing", func(d *Draft) (*Draft, error) { return d.Set("/a", []byte(`"two"`)) },
			`{ "a": "two", "list": [ "x", "y" ], "obj": { "k": true } }`},
		{"set new member", func(d *Draft) (*Draft, error) { return d.Set("/obj/new", []byte(`[1]`)) },
			`{ "a": 1, "list": [ "x", "y" ], "obj": { "k": true, "new": [ 1 ] } }`},
		{"set item", func(d *Draft) (*Draft, error) { return d.Set("/list/1", []byte(`"z"`)) },
			`{ "a": 1, "list": [ "x", "z" ], "obj": { "k": true } }`},
		{"insert at start", func(d *Draft) (*Draft, error) { return d.Insert("/list/0", []byte(`"w"`)) },
			`{ "a": 1, "list": [ "w", "x", "y" ], "obj": { "k": true } }`},
		{"insert in middle", func(d *Draft) (*Draft, error) { return d.Insert("/list/1", []byte(`"w"`)) },
			`{ "a": 1, "list": [ "x", "w", "y" ], "obj": { "k": true } }`},
		{"append", func(d *Draft) (*Draft, error) { return d.Insert("/list/-", []byte(`{"n": 1}`)) },
			`{ "a": 1, "list": [ "x", "y", { "n": 1 } ], "obj": { "k": true } }`},
		{"insert at end index", func(d *Draft) (*Draft, error) { return d.Insert("/list/2", []byte(`"w"`)) },
			`{ "a": 1, "list": [ "x", "y", "w" ], "obj": { "k": true } }`},
		{"remove member", func(d *Draft) (*Draft, error) { return d.Remove("/a") },
			`{ "list": [ "x", "y" ], "obj": { "k": true } }`},
		{"remove item", func(d *Draft) (*Draft, error) { return d.Remove("/list/0") },
			`{ "a": 1, "list": [ "y" ], "obj": { "k": true } }`},
		{"rename keeps order", func(d *Draft) (*Draft, error) { return d.Rename("/a", "b") },
			`{ "b": 1, "list": [ "x", "y" ], "obj": { "k": true } }`},
		{"replace root", func(d *Draft) (*Draft, error) { return d.Set("", []byte(`{"only": null}`)) },
			`{ "only": null }`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			edited, err := tt.edit(base)
			if err != nil {
				t.Fatal(err)
			}
			if got := mustCanonical(t, edited); got != tt.want {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
			if mustCanonical(t, base) != before {
				t.Fatal("the edit changed the original draft")
			}
			var walk func(n DraftNode)
			walk = func(n DraftNode) {
				if got := edited.At(n.Pointer()); got.Pointer() != n.Pointer() || got.Kind() != n.Kind() || got.Text() != n.Text() {
					t.Fatalf("pointer %q is stale", n.Pointer())
				}
				for _, k := range n.Keys() {
					walk(n.Member(k))
				}
				for _, item := range n.Items() {
					walk(item)
				}
			}
			walk(edited.Root())
		})
	}
}

func TestDraftEditErrors(t *testing.T) {
	base, err := ParseDraft([]byte(`{"a": 1, "list": ["x"], "b": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	// Under "a" (depth 1), maxPolicyDocumentDepth arrays reach the limit
	// exactly, as the parser allows; one more is over it.
	atLimit := strings.Repeat("[", maxPolicyDocumentDepth) + strings.Repeat("]", maxPolicyDocumentDepth)
	deep := "[" + atLimit + "]"
	if _, err := base.Set("/a", []byte(atLimit)); err != nil {
		t.Fatalf("a value at the nesting limit was refused: %v", err)
	}
	if _, err := ParseDraft([]byte(`{"a": ` + atLimit + `}`)); err != nil {
		t.Fatalf("the parser refuses what the edit allows: %v", err)
	}
	if _, err := ParseDraft([]byte(`{"a": ` + deep + `}`)); err == nil {
		t.Fatal("the parser allows what the edit refuses")
	}
	for name, edit := range map[string]func() (*Draft, error){
		"missing parent":      func() (*Draft, error) { return base.Set("/nope/x", []byte(`1`)) },
		"set past the end":    func() (*Draft, error) { return base.Set("/list/1", []byte(`1`)) },
		"insert out of range": func() (*Draft, error) { return base.Insert("/list/2", []byte(`1`)) },
		"insert into object":  func() (*Draft, error) { return base.Insert("/a/0", []byte(`1`)) },
		"remove absent":       func() (*Draft, error) { return base.Remove("/zz") },
		"rename onto taken":   func() (*Draft, error) { return base.Rename("/a", "b") },
		"rename an item":      func() (*Draft, error) { return base.Rename("/list/0", "x") },
		"bad JSON":            func() (*Draft, error) { return base.Set("/a", []byte(`{`)) },
		"duplicate key":       func() (*Draft, error) { return base.Set("/a", []byte(`{"k": 1, "k": 2}`)) },
		"no pointer":          func() (*Draft, error) { return base.Remove("") },
		"too deep":            func() (*Draft, error) { return base.Set("/a", []byte(deep)) },
	} {
		t.Run(name, func(t *testing.T) {
			if d, err := edit(); err == nil {
				t.Fatalf("edit accepted: %s", mustCanonical(t, d))
			}
		})
	}
}

// TestDraftEditKeepsAFixtureDecodable: editing a valid document through the
// draft yields one the decoder reads with the change applied.
func TestDraftEditKeepsAFixtureDecodable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "contracts", "policy", "v1", "signer_key_full.json"))
	if err != nil {
		t.Fatal(err)
	}
	draft, err := ParseDraft(data)
	if err != nil {
		t.Fatal(err)
	}
	edited, err := draft.Set("/max_fee_microalgos", []byte(`"5000"`))
	if err == nil {
		edited, err = edited.Remove("/transfer_policy/routes/4")
	}
	if err != nil {
		t.Fatal(err)
	}
	out, err := edited.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := edited.TopLevelString("key")
	doc, err := DecodePolicyV1(out, key, "signer")
	if err != nil {
		t.Fatal(err)
	}
	if doc.MaxFeeMicroAlgos != 5000 || len(doc.Routes) != 4 {
		t.Fatalf("decoded fee %d, %d routes", doc.MaxFeeMicroAlgos, len(doc.Routes))
	}
}
