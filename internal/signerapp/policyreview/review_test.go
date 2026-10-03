// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testKeyA      = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	testSignerDoc = `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"2000"}`
)

func testCosignerDoc(key string) string {
	return fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`, key)
}

func writePolicyFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadDocumentsEnforcesRoleShape(t *testing.T) {
	signer := writePolicyFile(t, "policy.json", testSignerDoc)
	if _, _, err := ReadDocuments([]string{signer, signer}, "signer", nil); err == nil {
		t.Fatal("two signer files accepted")
	}
	noKey := writePolicyFile(t, "nokey.json", `{"format":"aplane.cosigner-policy.v1"}`)
	if _, _, err := ReadDocuments([]string{noKey}, "cosigner", nil); err == nil || !strings.Contains(err.Error(), `"key"`) {
		t.Fatalf("cosigner file without key error = %v", err)
	}
	a := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	docs, names, err := ReadDocuments([]string{a}, "cosigner", nil)
	if err != nil || len(docs) != 1 || docs[0].Key != testKeyA || names[testKeyA] != a {
		t.Fatalf("ReadDocuments() = %+v, %v, %v", docs, names, err)
	}
	again := writePolicyFile(t, "again.json", testCosignerDoc(testKeyA))
	if _, _, err := ReadDocuments([]string{a, again}, "cosigner", nil); err == nil || !strings.Contains(err.Error(), "both policies") {
		t.Fatalf("duplicate key error = %v", err)
	}
	invalid := writePolicyFile(t, "invalid.json", "{\"format\":\"aplane.signer-policy.v1\",\"description\":\"\xff\"}")
	if _, _, err := ReadDocuments([]string{invalid}, "signer", nil); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	empty := writePolicyFile(t, "empty.json", "  \n")
	if _, _, err := ReadDocuments([]string{empty}, "signer", nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file error = %v", err)
	}
}

func TestDiffDocumentClassifiesNewAndIdenticalDocuments(t *testing.T) {
	next := testCosignerDoc(testKeyA)
	changes, identical, err := DiffDocument("cosigner", testKeyA, false, "", next)
	if err != nil || identical || len(changes) != 1 {
		t.Fatalf("new cosigner document: changes %+v identical %v err %v", changes, identical, err)
	}
	changes, identical, err = DiffDocument("cosigner", testKeyA, true, next, next)
	if err != nil || !identical || len(changes) != 0 {
		t.Fatalf("identical cosigner document: changes %+v identical %v err %v", changes, identical, err)
	}
	if _, _, err := DiffDocument("signer", "", false, "", testSignerDoc); err == nil {
		t.Fatal("signer diff without an active policy accepted")
	}

	var out bytes.Buffer
	PrintDiffs(&out, []DocumentDiff{{Label: "a.json", Identical: true}})
	if got := out.String(); got != "a.json: no changes\nno changes\n" || !Unchanged([]DocumentDiff{{Identical: true}}) {
		t.Fatalf("identical diff output = %q", got)
	}
}
