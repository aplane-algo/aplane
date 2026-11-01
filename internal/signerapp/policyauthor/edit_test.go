// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/policy"
)

const testAddress = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"

func TestEditSpecValues(t *testing.T) {
	for _, tt := range []struct {
		name     string
		spec     EditSpec
		input    string
		decimals uint64
		known    bool
		want     string
	}{
		{"bool yes", EditSpec{Kind: EditBool}, "yes", 0, false, "true"},
		{"bool false", EditSpec{Kind: EditBool}, "false", 0, false, "false"},
		{"choice", EditSpec{Kind: EditChoice, Choices: []string{"allow", "reject"}}, "reject", 0, false, `"reject"`},
		{"text", EditSpec{Kind: EditText}, ` a "quoted" note `, 0, false, `"a \"quoted\" note"`},
		{"ALGO display units", EditSpec{Kind: EditAmount, Asset: "algo"}, "1.5", 6, true, `"1500000"`},
		{"USDC display units", EditSpec{Kind: EditAmount}, "1,000", 6, true, `"1000000000"`},
		{"unknown decimals", EditSpec{Kind: EditAmount}, "125", 0, false, `"125"`},
		{"terms", EditSpec{Kind: EditTerms, Term: TermDestination}, "@ops, self, *, " + testAddress, 0, false, `["@ops","self","*","` + testAddress + `"]`},
		{"empty terms", EditSpec{Kind: EditTerms, Term: TermNetwork}, " , ", 0, false, `[]`},
		{"asset terms", EditSpec{Kind: EditTerms, Term: TermAsset}, "algo, asa:31566704, @usd", 0, false, `["algo","asa:31566704","@usd"]`},
		{"one term", EditSpec{Kind: EditTerm, Term: TermAddress}, testAddress, 0, false, `"` + testAddress + `"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.spec.Value(tt.input, tt.decimals, tt.known)
			if err != nil || string(got) != tt.want {
				t.Fatalf("Value(%q) = %s, %v; want %s", tt.input, got, err, tt.want)
			}
		})
	}
	for _, tt := range []struct {
		name  string
		spec  EditSpec
		input string
		known bool
		want  string
	}{
		{"bool", EditSpec{Kind: EditBool}, "maybe", false, "yes or no"},
		{"choice", EditSpec{Kind: EditChoice, Choices: []string{"allow"}}, "review", false, "choose one of"},
		{"too many decimals", EditSpec{Kind: EditAmount}, "1.0000001", true, "decimal places"},
		{"decimals unknown", EditSpec{Kind: EditAmount}, "12.5", false, "base units"},
		{"negative", EditSpec{Kind: EditAmount}, "-1", false, "base units"},
		{"bad checksum", EditSpec{Kind: EditTerm, Term: TermAddress}, testAddress[:57] + "B", false, "checksum"},
		{"self as a source", EditSpec{Kind: EditTerms, Term: TermSource}, "self", false, "not a valid address"},
		{"asa zero", EditSpec{Kind: EditTerms, Term: TermAsset}, "asa:0", false, "not an asset"},
		{"bare asa id", EditSpec{Kind: EditTerms, Term: TermAssetRef}, "31566704", false, "not an asset"},
		{"network", EditSpec{Kind: EditTerms, Term: TermNetwork}, "MainNet", false, "network token"},
		{"set in a blocked list", EditSpec{Kind: EditTerm, Term: TermAddress}, "@ops", false, "not a valid address"},
	} {
		t.Run("refuses "+tt.name, func(t *testing.T) {
			if _, err := tt.spec.Value(tt.input, 6, tt.known); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Value(%q) err = %v, want %q", tt.input, err, tt.want)
			}
		})
	}
}

func TestEditSpecDecimals(t *testing.T) {
	if d, src, ok := (EditSpec{Asset: "algo"}).Decimals(nil); !ok || d != 6 || src != asa.SourceBuiltin {
		t.Fatalf("ALGO: %d %s %v", d, src, ok)
	}
	if d, _, ok := (EditSpec{Network: "mainnet", Asset: "asa:31566704"}).Decimals(asa.BuiltinMetadata); !ok || d != 6 {
		t.Fatalf("USDC: %d %v", d, ok)
	}
	if _, _, ok := (EditSpec{Network: "mainnet", Asset: "asa:999999999"}).Decimals(asa.BuiltinMetadata); ok {
		t.Fatal("an unknown asset has known decimals")
	}
	if _, _, ok := (EditSpec{Network: "mainnet", Asset: "asa:31566704"}).Decimals(nil); ok {
		t.Fatal("no lookup gave decimals")
	}
}

// TestEveryFieldEditsToItself: for every editable field of the full signer
// and cosigner documents, entering the value the editor starts from leaves
// the document byte-for-byte as it was, so no editor can quietly change a
// value it only shows.
func TestEveryFieldEditsToItself(t *testing.T) {
	for _, name := range []string{"signer_key_full.json", "cosigner_key_full.json", "signer_default.json"} {
		f := LoadFile(writeFile(t, t.TempDir(), name, fixture(t, name)))
		before, _ := f.Draft.Canonical()
		edited := 0
		for _, s := range Outline(f, f.Problems, asa.BuiltinMetadata) {
			for _, fl := range s.Fields {
				if fl.Edit == nil || fl.Missing || fl.Absent {
					continue
				}
				decimals, _, known := fl.Edit.Decimals(asa.BuiltinMetadata)
				input := fl.Edit.Input(f.Draft.At(fl.Edit.Pointer), decimals, known)
				value, err := fl.Edit.Value(input, decimals, known)
				if err != nil {
					t.Errorf("%s %s: value %q refused: %v", name, fl.Pointer, input, err)
					continue
				}
				next, err := f.Draft.Set(fl.Edit.Pointer, value)
				if err != nil {
					t.Fatal(err)
				}
				if after, _ := next.Canonical(); string(after) != string(before) {
					t.Errorf("%s %s: editing to its own value %q changed the document", name, fl.Pointer, input)
				}
				edited++
			}
		}
		if edited < 10 {
			t.Fatalf("%s: only %d editable fields", name, edited)
		}
	}
}

// TestRemovalsAndAdds: every removal deletes what it names; the add actions
// create what they say, building missing parents, and refuse bad input.
func TestRemovalsAndAdds(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "a.json", fixture(t, "signer_key_full.json")))
	sections := Outline(f, f.Problems, asa.BuiltinMetadata)
	removals := 0
	for _, s := range sections {
		var rs []*Removal
		for _, fl := range s.Fields {
			if fl.Remove != nil {
				rs = append(rs, fl.Remove)
			}
		}
		if s.Remove != nil {
			rs = append(rs, s.Remove)
		}
		for _, r := range rs {
			next, err := r.Apply(f.Draft)
			if err != nil {
				t.Fatalf("%s: %v", r.Pointer, err)
			}
			// The value is gone, or an array item after it moved into its place.
			if after := next.At(r.Pointer); after.Exists() && compact(after) == compact(f.Draft.At(r.Pointer)) {
				t.Errorf("%s still present after removal", r.Pointer)
			}
			removals++
		}
	}
	if removals < 10 {
		t.Fatalf("only %d removals", removals)
	}

	// The minimal document has no limits, sets, blocked list or extra routes.
	minimal := LoadFile(writeFile(t, t.TempDir(), "m.json", fixture(t, "signer_key_minimal.json")))
	adds := map[string]AddAction{}
	for _, s := range Outline(minimal, nil, nil) {
		for _, a := range s.Adds {
			adds[a.Label] = a
		}
	}
	for _, tt := range []struct {
		label, input, pointer string
	}{
		{"Add a limit", "mainnet algo", "/limits/mainnet/algo/review_above"},
		{"Add a transaction type", "keyreg review", "/transaction_types/keyreg"},
		{"Add an address set", "ops", "/address_sets/ops"},
		{"Add an address set", "ops mainnet", "/address_sets/ops/mainnet"},
		{"Add an asset set", "usd mainnet", "/asset_sets/usd/mainnet"},
		{"Add a blocked destination", testAddress, "/transfer_policy/blocked_destinations/0"},
		{"Add a route", "payouts", "/transfer_policy/routes/0/id"},
	} {
		a, ok := adds[tt.label]
		if !ok {
			t.Fatalf("no %q action", tt.label)
		}
		next, err := a.Apply(minimal.Draft, tt.input)
		if err != nil {
			t.Fatalf("%s %q: %v", tt.label, tt.input, err)
		}
		if !next.At(tt.pointer).Exists() {
			t.Fatalf("%s %q: %s not created", tt.label, tt.input, tt.pointer)
		}
		if _, err := next.Canonical(); err != nil {
			t.Fatal(err)
		}
	}
	for label, input := range map[string]string{
		"Add a limit":               "mainnet",
		"Add a transaction type":    "teleport allow",
		"Add an address set":        "Bad Name!",
		"Add a blocked destination": "@ops",
		"Add a route":               "Bad Id",
	} {
		if _, err := adds[label].Apply(minimal.Draft, input); err == nil {
			t.Errorf("%s %q accepted", label, input)
		}
	}
	if _, err := adds["Add a limit"].Apply(f.Draft, "mainnet algo"); err == nil {
		t.Error("adding an existing limit was accepted")
	}
}

func TestCosignerChoicesAndThresholds(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, "cosigner_key_full.json")))
	for _, s := range Outline(f, nil, asa.BuiltinMetadata) {
		for _, fl := range s.Fields {
			if fl.Edit != nil && fl.Edit.Kind == EditChoice && strings.HasPrefix(fl.Pointer, "/transaction_types/") {
				if strings.Contains(strings.Join(fl.Edit.Choices, ","), "review") {
					t.Fatalf("%s offers review on a cosigner", fl.Pointer)
				}
			}
			if strings.HasSuffix(fl.Pointer, "/review_above") {
				t.Fatalf("a cosigner shows a review threshold field %s", fl.Pointer)
			}
		}
	}
	var adds []AddAction
	for _, s := range Outline(f, nil, nil) {
		adds = append(adds, s.Adds...)
	}
	for _, a := range adds {
		if a.Label == "Add a limit" {
			next, err := a.Apply(f.Draft, "testnet algo")
			if err != nil {
				t.Fatal(err)
			}
			if !next.At("/limits/testnet/algo/reject_above").Exists() || next.At("/limits/testnet/algo/review_above").Exists() {
				t.Fatal("a cosigner limit is not a reject threshold")
			}
		}
	}
}

// TestBrokenContainersCanBeRepaired: for each required container, missing or
// of the wrong type, some action on the outline makes it the right type
// again, so no parsable draft is stuck.
func TestBrokenContainersCanBeRepaired(t *testing.T) {
	base := string(fixture(t, "signer_key_minimal.json"))
	draftOf := func(t *testing.T, doc string) *File {
		t.Helper()
		return LoadFile(writeFile(t, t.TempDir(), "d.json", []byte(doc)))
	}
	for _, tt := range []struct {
		name, pointer, kind string
		doc                 string
	}{
		{"transfer_policy wrong type", "/transfer_policy", "object", replaceMember(t, base, "transfer_policy", "42")},
		{"transfer_policy missing", "/transfer_policy", "object", removeMember(t, base, "transfer_policy")},
		{"transaction_types wrong type", "/transaction_types", "object", replaceMember(t, base, "transaction_types", `"all"`)},
		{"transaction_types missing", "/transaction_types", "object", removeMember(t, base, "transaction_types")},
		{"routes wrong type", "/transfer_policy/routes", "array", strings.Replace(base, `"routes": []`, `"routes": 5`, 1)},
		{"document not an object", "", "object", `[1, 2]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := draftOf(t, tt.doc)
			if f.Draft == nil {
				t.Fatalf("test document does not parse:\n%s", tt.doc)
			}
			repaired := false
			for _, s := range Outline(f, f.Problems, nil) {
				for _, a := range s.Adds {
					next, err := a.Apply(f.Draft, "")
					if err == nil && next.At(tt.pointer).Kind() == tt.kind {
						repaired = true
					}
				}
			}
			if !repaired {
				t.Fatalf("no action makes %q a%s %s", tt.pointer, map[bool]string{true: "n", false: ""}[tt.kind == "object" || tt.kind == "array"], tt.kind)
			}
		})
	}
}

func replaceMember(t *testing.T, doc, name, value string) string {
	t.Helper()
	d, err := policy.ParseDraft([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	next, err := d.Set("/"+name, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := next.Canonical()
	return string(out)
}

func removeMember(t *testing.T, doc, name string) string {
	t.Helper()
	d, err := policy.ParseDraft([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	next, err := d.Remove("/" + name)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := next.Canonical()
	return string(out)
}

func TestCopyActions(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "a.json", fixture(t, "signer_key_full.json")))
	sections := Outline(f, nil, nil)
	byID := map[string]Section{}
	for _, s := range sections {
		byID[s.ID] = s
	}

	route := byID["route:1"]
	if route.Copy == nil || !route.Copy.NeedsInput() {
		t.Fatal("a route has no copy action that asks for an id")
	}
	if _, err := route.Copy.Apply(f.Draft, "Bad Id"); err == nil {
		t.Fatal("a bad route id was accepted")
	}
	next, err := route.Copy.Apply(f.Draft, "treasury-to-ops-2")
	if err != nil {
		t.Fatal(err)
	}
	if id := next.At("/transfer_policy/routes/2/id").Text(); id != "treasury-to-ops-2" || next.At("/transfer_policy/routes/1/id").Text() != "treasury-to-ops" {
		t.Fatalf("copy is not right after the original: %q", id)
	}
	if compact(next.At("/transfer_policy/routes/2/sources")) != compact(f.Draft.At("/transfer_policy/routes/1/sources")) {
		t.Fatal("the copy does not carry the route's fields")
	}
	out, _ := next.Canonical()
	if _, err := policy.DecodePolicyV1(out, f.Key, "signer"); err != nil {
		t.Fatalf("document with the copied route does not decode: %v", err)
	}

	var setCopy AddAction
	for _, a := range byID["address_sets"].Adds {
		if a.Label == "Copy an address set" {
			setCopy = a
		}
	}
	next, err = setCopy.Apply(f.Draft, "@ops ops-backup")
	if err != nil || compact(next.At("/address_sets/ops-backup")) != compact(f.Draft.At("/address_sets/ops")) {
		t.Fatalf("set copy: %v", err)
	}
	if _, err := setCopy.Apply(f.Draft, "nope copy"); err == nil {
		t.Fatal("copying an unknown set was accepted")
	}
	if _, err := setCopy.Apply(f.Draft, "ops treasury"); err == nil {
		t.Fatal("copying onto an existing set was accepted")
	}

	var member *AddAction
	for _, fl := range byID["blocked"].Fields {
		if fl.Copy != nil {
			member = fl.Copy
		}
	}
	if member == nil || member.NeedsInput() {
		t.Fatal("a blocked address has no direct copy")
	}
	next, err = member.Apply(f.Draft, "")
	if err != nil || len(next.At("/transfer_policy/blocked_destinations").Items()) != 2 {
		t.Fatalf("duplicate member: %v", err)
	}

	c := LoadFile(writeFile(t, t.TempDir(), "c.json", fixture(t, "cosigner_key_full.json")))
	for _, s := range Outline(c, nil, nil) {
		if s.ID == "rekey" {
			next, err := s.Fields[0].Copy.Apply(c.Draft, "")
			if err != nil || len(next.At("/rekey_policy/allowed").Items()) != 2 {
				t.Fatalf("duplicate rekey edge: %v", err)
			}
		}
	}
}
