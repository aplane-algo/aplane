// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// node.yaml is durable: SaveInitial writes these exact bytes.
func TestSaveInitialWritesCanonicalNodeYAML(t *testing.T) {
	createdAt := time.Date(2026, 6, 7, 12, 30, 0, 0, time.FixedZone("T", 3600))
	for _, tc := range []struct {
		role Role
		want string
	}{
		{RoleSigner, "schema_version: 1\nrole: signer\ncreated_at: \"2026-06-07T11:30:00Z\"\n"},
		{RoleCosigner, "schema_version: 1\nrole: cosigner\ncreated_at: \"2026-06-07T11:30:00Z\"\n"},
		{" Cosigner ", "schema_version: 1\nrole: cosigner\ncreated_at: \"2026-06-07T11:30:00Z\"\n"},
	} {
		paths := storepaths.NewPaths(t.TempDir())
		roleBytes, err := SaveInitial(paths, tc.role, createdAt)
		if err != nil {
			t.Fatalf("SaveInitial(%q) error = %v", tc.role, err)
		}
		onDisk, err := os.ReadFile(paths.NodeRolePath())
		if err != nil {
			t.Fatal(err)
		}
		if string(roleBytes) != tc.want || string(onDisk) != tc.want {
			t.Fatalf("SaveInitial(%q) = %q, on disk %q, want %q", tc.role, roleBytes, onDisk, tc.want)
		}
	}
	if _, err := SaveInitial(storepaths.NewPaths(t.TempDir()), "operator", createdAt); err == nil {
		t.Fatal("SaveInitial accepted an unknown role")
	}
}
