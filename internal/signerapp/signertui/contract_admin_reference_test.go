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
	keyID := strings.TrimSuffix(filepath.Base(validPath), ".wit.json")
	wrongID := strings.Replace(string(data), keyID, strings.Repeat("A", len(keyID)), 1)
	cases := []struct {
		name string
		path string
		want string
	}{
		{"private artifact extension", write("private.wit", data), ".wit.json"},
		{"malformed JSON", write("malformed.wit.json", []byte(`{"schema":`)), "invalid contract-admin reference"},
		{"wrong key ID", write("wrong.wit.json", []byte(wrongID)), "witness_key_id does not match"},
		{"oversized file", write("large.wit.json", []byte(strings.Repeat("x", maxContractAdminReferenceBytes+1))), "size limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContractAdminPublicKey(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadContractAdminPublicKey(%q) error = %v, want %q", tc.path, err, tc.want)
			}
		})
	}
	link := filepath.Join(dir, "link.wit.json")
	if err := os.Symlink(validPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadContractAdminPublicKey(link); err == nil {
		t.Fatal("symlinked public reference was accepted")
	}
}
