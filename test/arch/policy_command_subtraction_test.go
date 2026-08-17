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
}
