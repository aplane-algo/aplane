// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadContractAdminPublicKeyRejectsInvalidReference(t *testing.T) {
	validPath, _ := writeContractAdminReference(t)
	data, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, content []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keyID := strings.TrimSuffix(filepath.Base(validPath), ".cos.json")
	wrongID := strings.Replace(string(data), keyID, strings.Repeat("A", len(keyID)), 1)
	cases := []struct {
		name string
		path string
		want string
	}{
		{"private artifact extension", write("private.cos", data), ".cos.json"},
		{"unrelated extension", write("reference.txt", data), ".cos.json"},
		{"malformed JSON", write("malformed.cos.json", []byte(`{"schema":`)), "invalid contract-admin reference"},
		{"wrong key ID", write("wrong.cos.json", []byte(wrongID)), "witness_key_id does not match"},
		{"oversized file", write("large.cos.json", []byte(strings.Repeat("x", maxContractAdminReferenceBytes+1))), "size limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContractAdminPublicKey(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadContractAdminPublicKey(%q) error = %v, want %q", tc.path, err, tc.want)
			}
		})
	}
	link := filepath.Join(dir, "link.cos.json")
	if err := os.Symlink(validPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadContractAdminPublicKey(link); err == nil {
		t.Fatal("symlinked public reference was accepted")
	}
}

func TestLoadContractAdminPublicKeyAcceptsLegacyReference(t *testing.T) {
	path, want := writeContractAdminReference(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".cos.json", ".wit.json", ".adm.json"} {
		refPath := filepath.Join(t.TempDir(), "reference"+suffix)
		if err := os.WriteFile(refPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadContractAdminPublicKey(refPath)
		if err != nil || got != want {
			t.Fatalf("public key from %s = %q, %v; want %q", suffix, got, err, want)
		}
	}
}
