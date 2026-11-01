// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"strings"
	"testing"
)

func loadText(t *testing.T, name, text string) *File {
	t.Helper()
	return LoadFile(writeFile(t, t.TempDir(), name, []byte(text)))
}

func changeText(c Comparison) string {
	var lines []string
	for _, ch := range c.Changes {
		lines = append(lines, ch.Effect+" "+ch.Path+" "+ch.Summary)
	}
	return strings.Join(lines, "\n")
}

func TestComparePolicyMode(t *testing.T) {
	base := string(fixture(t, "signer_key_full.json"))
	same := loadText(t, "a.json", base)
	if c := Compare(same, loadText(t, "b.json", base)); c.Mode != ComparePolicy || !c.Identical || len(c.Changes) != 0 {
		t.Fatalf("identical files: %+v", c)
	}
	tighter := strings.Replace(base, `"max_fee_microalgos": "10000"`, `"max_fee_microalgos": "5000"`, 1)
	c := Compare(same, loadText(t, "b.json", tighter))
	if c.Mode != ComparePolicy || c.Identical || !strings.Contains(changeText(c), "tightened /max_fee_microalgos") {
		t.Fatalf("tighter fee: %+v", c)
	}
	// A key's own document against the default it would replace.
	def := loadText(t, "default.json", string(fixture(t, "signer_default.json")))
	c = Compare(def, same)
	if c.Mode != ComparePolicy || c.Identical || !strings.Contains(c.Note, "replaces the default wholesale") {
		t.Fatalf("key against default: %+v", c)
	}
	// Reformatting changes nothing.
	f := loadText(t, "c.json", base)
	canonical, _ := f.Canonical()
	spaced := strings.ReplaceAll(string(canonical), "  ", "    ")
	if c := Compare(same, loadText(t, "d.json", spaced)); !c.Identical {
		t.Fatalf("reindented file: %+v", c)
	}
}

func TestCompareStructureModeForInvalidDrafts(t *testing.T) {
	a := loadText(t, "a.json", `{"format": "aplane.policy.v1", "role": "signer", "x": 1, "list": [1, 2], "gone": true}`)
	b := loadText(t, "b.json", `{"format": "aplane.policy.v1", "role": "signer", "x": 2, "list": [1], "new": "v"}`)
	c := Compare(a, b)
	got := changeText(c)
	for _, want := range []string{"changed /x 1 -> 2", "removed /list/1 2", "removed /gone true", `added /new "v"`} {
		if !strings.Contains(got, want) {
			t.Errorf("structure diff lacks %q:\n%s", want, got)
		}
	}
	if c.Mode != CompareStructure || c.Identical {
		t.Fatalf("mode %s identical %v", c.Mode, c.Identical)
	}
}

func TestCompareTextModeForAnUnparsableFile(t *testing.T) {
	a := loadText(t, "a.json", "{\n  \"a\": 1,\n  \"b\": 2\n}\n")
	b := loadText(t, "b.json", "{\n  \"a\": 1,\n  \"b\": 3\n")
	c := Compare(a, b)
	got := changeText(c)
	if c.Mode != CompareText || !strings.Contains(got, `removed line 3   "b": 2`) || !strings.Contains(got, `added line 3   "b": 3`) || !strings.Contains(got, "removed line 4 }") {
		t.Fatalf("text diff (%s):\n%s", c.Mode, got)
	}
	if c := Compare(a, loadText(t, "c.json", string(a.Loaded))); !c.Identical {
		t.Fatalf("identical bytes: %+v", c)
	}
	big := strings.Repeat("x\n", 3000)
	if c := compareText([]byte(big), []byte(big+"y\n"+big)); !strings.Contains(c.Note, "too large") || len(c.Changes) != 0 {
		t.Fatalf("large files: %+v", c)
	}
}

func TestWorkspaceDefault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", fixture(t, "signer_default.json"))
	writeFile(t, dir, "k.json", fixture(t, "signer_key_full.json"))
	w, _ := Open(dir)
	if d := w.Default(); d == nil || d.Key != "default" {
		t.Fatalf("default = %+v", d)
	}
	writeFile(t, dir, "b.json", fixture(t, "signer_default.json"))
	w, _ = Open(dir)
	if d := w.Default(); d != nil {
		t.Fatal("two defaults gave one")
	}
}

// TestCompareStructureShowsTypeChanges: a value that changes type shows as
// JSON on both sides, so false and "false" are told apart.
func TestCompareStructureShowsTypeChanges(t *testing.T) {
	base := string(fixture(t, "signer_key_minimal.json"))
	changed := strings.Replace(base, `"reject_clawback": false`, `"reject_clawback": "false"`, 1)
	if changed == base {
		t.Fatal("test did not change the document")
	}
	c := Compare(loadText(t, "a.json", base), loadText(t, "b.json", changed))
	if c.Mode != CompareStructure || !strings.Contains(changeText(c), `changed /reject_clawback false -> "false"`) {
		t.Fatalf("type change (%s):\n%s", c.Mode, changeText(c))
	}
}
