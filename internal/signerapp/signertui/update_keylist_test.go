// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveTEALToFileRequiresCanonicalAddressFilename(t *testing.T) {
	dataDir := t.TempDir()
	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	path, err := saveTEALToFile(dataDir, strings.ToLower(address), "int 1\n")
	if err != nil {
		t.Fatalf("saveTEALToFile() error = %v", err)
	}
	want := filepath.Join(dataDir, "files", address+".teal")
	if path != want {
		t.Fatalf("saveTEALToFile() path = %q, want %q", path, want)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "int 1\n" {
		t.Fatalf("saved TEAL = %q, err = %v", data, err)
	}

	if _, err := saveTEALToFile(dataDir, "../../outside", "int 0\n"); err == nil || !strings.Contains(err.Error(), "invalid account address") {
		t.Fatalf("saveTEALToFile(path traversal) error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "outside.teal")); !os.IsNotExist(err) {
		t.Fatalf("invalid address created an outside file: %v", err)
	}
}
