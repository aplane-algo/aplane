// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetiredAppolicyArtifactDoesNotReturn(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "cmd", "appolicy")); !os.IsNotExist(err) {
		t.Fatalf("retired cmd/appolicy exists: %v", err)
	}
	for _, relative := range []string{"Makefile", filepath.Join(".github", "workflows", "release.yml")} {
		path := filepath.Join(root, relative)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(data)), "appolicy") {
			t.Errorf("%s still contains the retired appolicy build/release artifact", relative)
		}
	}
	userPolicy := filepath.Join(root, "docs", "USER_POLICY.md")
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" || path == userPolicy {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(data)), "appolicy") {
			t.Errorf("%s still documents the retired policy binary", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(userPolicy)
	if err != nil {
		t.Fatal(err)
	}
	const migrationStart = "### Migration from the retired policy binary"
	const migrationEnd = "## Top-Level Fields"
	text := string(data)
	start := strings.Index(text, migrationStart)
	end := strings.Index(text, migrationEnd)
	if start < 0 || end <= start {
		t.Fatal("USER_POLICY migration section markers are missing or out of order")
	}
	withoutMigration := text[:start] + text[end:]
	if strings.Contains(strings.ToLower(withoutMigration), "appolicy") {
		t.Error("USER_POLICY documents the retired binary outside its migration section")
	}
}
