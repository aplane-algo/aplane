// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/policy"
)

func outlineFixture(t *testing.T, name string) (*File, []Section) {
	t.Helper()
	f := LoadFile(writeFile(t, t.TempDir(), filepath.Base(name), fixture(t, name)))
	return f, Outline(f, f.Problems, asa.BuiltinMetadata)
}

// TestOutlineShowsEveryValue: for every parsable fixture, every scalar in the
// document is inside some field's pointer, so nothing in a file is hidden.
func TestOutlineShowsEveryValue(t *testing.T) {
	names := []string{"signer_default.json", "signer_key_full.json", "signer_key_minimal.json", "signer_uint64_max.json",
		"cosigner_default.json", "cosigner_key_full.json", "cosigner_key_minimal.json", "cosigner_key_no_wildcard.json"}
	for _, pattern := range []string{"semantic_invalid/*.json", "invalid/*.json"} {
		matches, _ := filepath.Glob(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", pattern))
		for _, m := range matches {
			names = append(names, strings.TrimPrefix(filepath.ToSlash(m), "../../../test/contracts/policy/v1/"))
		}
	}
	for _, name := range names {
		f, sections := outlineFixture(t, name)
		if f.Draft == nil {
			continue
		}
		var pointers []string
		for _, s := range sections {
			for _, fl := range s.Fields {
				if fl.Pointer != "" || fl.Label == "document" {
					pointers = append(pointers, fl.Pointer)
				}
			}
		}
		var walk func(n policy.DraftNode)
		walk = func(n policy.DraftNode) {
			switch n.Kind() {
			case "object":
				for _, k := range n.Keys() {
					walk(n.Member(k))
				}
				return
			case "array":
				if len(n.Items()) == 0 {
					break
				}
				for _, item := range n.Items() {
					walk(item)
				}
				return
			}
			for _, p := range pointers {
				if covers(p, n.Pointer()) {
					return
				}
			}
			t.Errorf("%s: %s (%s) is shown by no field", name, n.Pointer(), n.Kind())
		}
		walk(f.Draft.Root())
	}
}

// TestOutlineAttachesEveryProblem: every problem lands somewhere, and on the
// most specific field whose pointer covers it when there is one.
func TestOutlineAttachesEveryProblem(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "semantic_invalid", "*.json"))
	for _, m := range append(matches, filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "signer_key_full.json")) {
		name := strings.TrimPrefix(filepath.ToSlash(m), "../../../test/contracts/policy/v1/")
		f, sections := outlineFixture(t, name)
		attached := 0
		for _, s := range sections {
			attached += len(s.Problems)
			for _, fl := range s.Fields {
				for _, p := range fl.Problems {
					attached++
					if !covers(fl.Pointer, p.Pointer) && !fl.Missing {
						t.Errorf("%s: problem at %q attached to field %q", name, p.Pointer, fl.Pointer)
					}
				}
			}
		}
		if attached != len(f.Problems) {
			t.Errorf("%s: %d of %d problems attached", name, attached, len(f.Problems))
		}
	}
}

func outlineOf(t *testing.T, doc string) []Section {
	t.Helper()
	f := LoadFile(writeFile(t, t.TempDir(), "d.json", []byte(doc)))
	return Outline(f, f.Problems, asa.BuiltinMetadata)
}

func findField(sections []Section, pointer string) (Section, Field, bool) {
	for _, s := range sections {
		for _, f := range s.Fields {
			if f.Pointer == pointer {
				return s, f, true
			}
		}
	}
	return Section{}, Field{}, false
}

func TestOutlineMarksMissingAndUnknownFields(t *testing.T) {
	doc := regexp.MustCompile(`"reject_clawback": (true|false),`).ReplaceAllString(string(fixture(t, "signer_key_minimal.json")), `"zz_extra": [1, 2],`)
	if !strings.Contains(doc, "zz_extra") {
		t.Fatal("test did not edit the document")
	}
	sections := outlineOf(t, doc)
	_, missing, ok := findField(sections, "/reject_clawback")
	if !ok || !missing.Missing || missing.Value != "(missing)" || len(missing.Problems) != 1 || !strings.Contains(missing.Problems[0].Message, "reject_clawback") {
		t.Fatalf("missing field = %+v (found %v)", missing, ok)
	}
	s, unknown, ok := findField(sections, "/zz_extra")
	if !ok || !unknown.Unknown || s.Title != "Other fields" || unknown.Value != "1, 2" {
		t.Fatalf("unknown field = %+v in %q (found %v)", unknown, s.Title, ok)
	}
}

func TestOutlineDisplaysValues(t *testing.T) {
	sections := outlineOf(t, string(fixture(t, "signer_key_full.json")))
	for pointer, want := range map[string]string{
		"/reject_clawback":                        "yes",
		"/max_fee_microalgos":                     "0.01 ALGO (10000 microAlgos)",
		"/transfer_policy/close_on_no_route":      "review",
		"/limits/mainnet/asa:31566704":            "reject above 5000 USDC (5000000000 base units; 6 decimals, builtin)",
		"/transfer_policy/routes/1/sources":       "@treasury",
		"/address_sets/ops/mainnet/0":             "EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI",
		"/transfer_policy/blocked_destinations/0": "KVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVDNKFTE",
	} {
		_, f, ok := findField(sections, pointer)
		if !ok || f.Value != want {
			t.Errorf("%s = %q (found %v), want %q", pointer, f.Value, ok, want)
		}
	}
	var titles []string
	for _, s := range sections {
		titles = append(titles, strings.Repeat("  ", s.Depth)+s.Title)
	}
	got := strings.Join(titles, "\n")
	for _, want := range []string{"Summary", "Guards", "Fee cap", "Transaction types", "Limits", "Address sets (2)", "Asset sets (1)", "Transfers", "  Miss actions", "  Blocked destinations (1)", "  Routes (5)", "    Route treasury-to-ops"} {
		if !strings.Contains(got, want) {
			t.Errorf("outline lacks %q:\n%s", want, got)
		}
	}
}

func TestOutlineForACosignerDocument(t *testing.T) {
	sections := outlineOf(t, string(fixture(t, "cosigner_key_no_wildcard.json")))
	if _, _, ok := findField(sections, "/reject_rekey"); !ok {
		t.Fatal("cosigner guard reject_rekey missing")
	}
	for _, s := range sections {
		if s.ID == "miss" {
			t.Fatal("a cosigner outline has miss actions")
		}
		for _, f := range s.Fields {
			if f.Pointer == "/always_review_warnings" || f.Pointer == "/reject_foreign_rekey" {
				t.Fatalf("a cosigner outline shows signer field %s", f.Pointer)
			}
		}
	}
	wildcard := false
	for _, s := range sections {
		for _, f := range s.Fields {
			if strings.HasPrefix(f.Label, "*") && f.Value == "reject" && f.Pointer == "" {
				wildcard = true
			}
		}
	}
	if !wildcard {
		t.Fatal("an omitted cosigner * is not shown as reject")
	}
}

func TestOutlineOfAnUnparsableFile(t *testing.T) {
	f := LoadFile(writeFile(t, t.TempDir(), "bad.json", []byte("{")))
	sections := Outline(f, f.Problems, nil)
	if len(sections) != 1 || len(sections[0].Problems) != 1 || !strings.Contains(sections[0].Title, "unparsable") {
		t.Fatalf("sections = %+v", sections)
	}
	if all, errs := sections[0].ProblemCount(); all != 1 || errs != 1 {
		t.Fatalf("count = %d, %d", all, errs)
	}
}
