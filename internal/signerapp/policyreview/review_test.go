// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

const (
	testKeyA = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	testKeyB = "GMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZT"
)

var testSignerDoc = policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, `{"max_fee_microalgos":"2000"}`)

func testCosignerDoc(key string) string {
	return policytest.MustDocument(noderole.RoleCosigner, key, "")
}

func writePolicyFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadDocumentsNamesEachDocumentByItsKey(t *testing.T) {
	signer := writePolicyFile(t, "default.json", testSignerDoc)
	docs, names, err := ReadDocuments([]string{signer}, nil)
	if err != nil || len(docs) != 1 || docs[0].Key != policy.DefaultKey || names[policy.DefaultKey] != signer {
		t.Fatalf("ReadDocuments(default) = %+v, %v, %v", docs, names, err)
	}
	if _, _, err := ReadDocuments([]string{signer, signer}, nil); err == nil || !strings.Contains(err.Error(), "both policies") {
		t.Fatalf("two files for the default error = %v", err)
	}
	noKey := writePolicyFile(t, "nokey.json", `{"format":"aplane.policy.v1"}`)
	if _, _, err := ReadDocuments([]string{noKey}, nil); err == nil || !strings.Contains(err.Error(), `"key"`) {
		t.Fatalf("file without key error = %v", err)
	}
	a := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	docs, names, err = ReadDocuments([]string{a}, nil)
	if err != nil || len(docs) != 1 || docs[0].Key != testKeyA || names[testKeyA] != a {
		t.Fatalf("ReadDocuments() = %+v, %v, %v", docs, names, err)
	}
	again := writePolicyFile(t, "again.json", testCosignerDoc(testKeyA))
	if _, _, err := ReadDocuments([]string{a, again}, nil); err == nil || !strings.Contains(err.Error(), "both policies") {
		t.Fatalf("duplicate key error = %v", err)
	}
	invalid := writePolicyFile(t, "invalid.json", "{\"key\":\"default\",\"description\":\"\xff\"}")
	if _, _, err := ReadDocuments([]string{invalid}, nil); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	empty := writePolicyFile(t, "empty.json", "  \n")
	if _, _, err := ReadDocuments([]string{empty}, nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file error = %v", err)
	}
}

func TestReadRegularDocumentsRejectsNonRegularPaths(t *testing.T) {
	file := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	docs, names, err := ReadRegularDocuments([]string{file})
	if err != nil || len(docs) != 1 || docs[0].Key != testKeyA || docs[0].Document != testCosignerDoc(testKeyA) || names[testKeyA] != file {
		t.Fatalf("ReadRegularDocuments() = %+v, %v, %v", docs, names, err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, t.TempDir(), "-", filepath.Join(t.TempDir(), "missing.json")} {
		if _, _, err := ReadRegularDocuments([]string{path}); err == nil {
			t.Fatalf("ReadRegularDocuments(%s) accepted a path that is not a regular file", path)
		}
	}
	empty := writePolicyFile(t, "empty.json", "  \n")
	if _, _, err := ReadRegularDocuments([]string{empty}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file error = %v", err)
	}
}

func TestDiffCandidateComparesWithTheGoverningDocument(t *testing.T) {
	def := policytest.EmbeddedDefault(t, noderole.RoleCosigner)
	next := testCosignerDoc(testKeyA)
	// A key gaining its first document is compared with the default it
	// followed, and is a change even when nothing else differs.
	changes, identical, err := DiffCandidate(noderole.RoleCosigner, testKeyA, def, next, false)
	if err != nil || identical || len(changes) == 0 || changes[0].Path != "/" || !strings.Contains(changes[0].Summary, "policy of its own") {
		t.Fatalf("new document: changes %+v identical %v err %v", changes, identical, err)
	}
	// A key's own document compared with an equal candidate is identical.
	changes, identical, err = DiffCandidate(noderole.RoleCosigner, testKeyA, next, next, true)
	if err != nil || !identical || len(changes) != 0 {
		t.Fatalf("identical document: changes %+v identical %v err %v", changes, identical, err)
	}
	// The default compared with itself is identical too.
	if _, identical, err := DiffCandidate(noderole.RoleCosigner, policy.DefaultKey, def, def, true); err != nil || !identical {
		t.Fatalf("identical default: identical %v err %v", identical, err)
	}
	if _, _, err := DiffCandidate(noderole.RoleSigner, testKeyA, def, next, false); err == nil {
		t.Fatal("a cosigner document diffed on a signer node")
	}

	removal, err := DiffRemoval(noderole.RoleCosigner, testKeyA, next, def)
	if err != nil || len(removal) == 0 || removal[0].Path != "/" || !strings.Contains(removal[0].Summary, "follows the node default") {
		t.Fatalf("removal: changes %+v err %v", removal, err)
	}
	// The minimal document allows pay and axfer; the deny-all default does
	// not, so losing the document tightens those types.
	rendered := ""
	for _, c := range removal {
		rendered += string(c.Effect) + " " + c.Path + "\n"
	}
	if !strings.Contains(rendered, "tightened /transaction_types/pay") {
		t.Fatalf("removal diff does not show the default's effect:\n%s", rendered)
	}

	var out bytes.Buffer
	PrintDiffs(&out, []DocumentDiff{{Label: "a.json", Identical: true}})
	if got := out.String(); got != "a.json: no changes\n" || !Unchanged([]DocumentDiff{{Identical: true}}) {
		t.Fatalf("identical diff output = %q", got)
	}

	// Each change carries its own mark; no closing count repeats them.
	out.Reset()
	PrintDiffs(&out, []DocumentDiff{{Label: "b.json", Changes: []policy.PolicyChange{
		{Effect: policy.PolicyChangeLoosened, Path: "/", Summary: "new policy"},
		{Effect: policy.PolicyChangeTightened, Path: "/reject_clawback", Summary: "false → true"},
	}}})
	want := "b.json:\n  loosened   /: new policy\n  tightened  /reject_clawback: false → true\n"
	if got := out.String(); got != want {
		t.Fatalf("diff output = %q, want %q", got, want)
	}

	out.Reset()
	PrintDiffs(&out, nil)
	if got := out.String(); got != "no changes\n" {
		t.Fatalf("empty diff output = %q", got)
	}
}

func TestDocumentFromTextAppliesTheFileRules(t *testing.T) {
	doc, err := DocumentFromText("edited.json", testCosignerDoc(testKeyA))
	if err != nil || doc.Key != testKeyA || !strings.Contains(doc.Document, testKeyA) {
		t.Fatalf("cosigner text: doc %+v err %v", doc, err)
	}
	doc, err = DocumentFromText("default.json", testSignerDoc)
	if err != nil || doc.Key != policy.DefaultKey || doc.Document != testSignerDoc {
		t.Fatalf("signer text: doc %+v err %v", doc, err)
	}
	for name, text := range map[string]string{
		"empty":        " \n",
		"no key":       `{"format":"aplane.policy.v1"}`,
		"not utf-8":    "{\"key\":\"" + testKeyA + "\xff\"}",
		"over the cap": strings.Repeat(" ", MaxPolicyBytes+1),
	} {
		if _, err := DocumentFromText("edited.json", text); err == nil {
			t.Fatalf("%s: text accepted", name)
		}
	}
}
