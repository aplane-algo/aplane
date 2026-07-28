// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/noderole"
)

// stageArchiveForManifest writes a small archive tree and seals its manifest.
func stageArchiveForManifest(t *testing.T, passphrase []byte) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "apb"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "apb", "ADDR.apb"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile(payload): %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("readme"), 0o600); err != nil {
		t.Fatalf("WriteFile(readme): %v", err)
	}
	autoApprove := false
	if err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		SourceSettingsSnapshot{UserAutoApprove: &autoApprove},
		passphrase,
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
	return root
}

func TestSealedManifestRoundTrip(t *testing.T) {
	passphrase := []byte("export-passphrase")
	root := stageArchiveForManifest(t, passphrase)

	manifest, err := OpenSealedManifest(root, passphrase)
	if err != nil {
		t.Fatalf("OpenSealedManifest() error = %v", err)
	}
	if manifest.SourceNodeRole != string(noderole.RoleSigner) {
		t.Fatalf("SourceNodeRole = %q", manifest.SourceNodeRole)
	}
	if len(manifest.Members) != 2 {
		t.Fatalf("members = %+v, want the payload and the readme", manifest.Members)
	}
	// The manifest never inventories itself.
	for _, member := range manifest.Members {
		if member.Path == ManifestFileName {
			t.Fatal("manifest inventoried itself")
		}
	}
}

func TestSealedManifestRejectsWrongPassphrase(t *testing.T) {
	root := stageArchiveForManifest(t, []byte("export-passphrase"))
	if _, err := OpenSealedManifest(root, []byte("wrong-passphrase")); err == nil {
		t.Fatal("OpenSealedManifest accepted a wrong passphrase")
	}
}

// TestSealedManifestDetectsTampering covers the attacker-without-the-passphrase
// cases that per-payload authentication cannot see: a removed member, an added
// member, and altered member content.
func TestSealedManifestDetectsTampering(t *testing.T) {
	passphrase := []byte("export-passphrase")

	t.Run("removed member", func(t *testing.T) {
		root := stageArchiveForManifest(t, passphrase)
		if err := os.Remove(filepath.Join(root, "apb", "ADDR.apb")); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		_, err := OpenSealedManifest(root, passphrase)
		if err == nil || !strings.Contains(err.Error(), "missing member") {
			t.Fatalf("OpenSealedManifest() error = %v, want missing-member rejection", err)
		}
	})

	t.Run("added member", func(t *testing.T) {
		root := stageArchiveForManifest(t, passphrase)
		if err := os.WriteFile(filepath.Join(root, "apb", "EVIL.apb"), []byte("smuggled"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := OpenSealedManifest(root, passphrase)
		if err == nil || !strings.Contains(err.Error(), "unlisted member") {
			t.Fatalf("OpenSealedManifest() error = %v, want unlisted-member rejection", err)
		}
	})

	t.Run("altered member", func(t *testing.T) {
		root := stageArchiveForManifest(t, passphrase)
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("tampered"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := OpenSealedManifest(root, passphrase)
		if err == nil || !strings.Contains(err.Error(), "does not match the sealed manifest") {
			t.Fatalf("OpenSealedManifest() error = %v, want digest-mismatch rejection", err)
		}
	})
}

func TestSealedManifestRejectsArchiveWithoutManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "apb"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, err := OpenSealedManifest(root, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "unsupported backup archive format") {
		t.Fatalf("OpenSealedManifest() error = %v, want unsupported-format rejection", err)
	}
}

func TestSealedManifestCarriesSourceContext(t *testing.T) {
	passphrase := []byte("export-passphrase")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "apb"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "apb", "ADDR.apb"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	autoApprove := true
	if err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		SourceSettingsSnapshot{
			UserAutoApprove:     &autoApprove,
			GenesisHashMappings: map[string]string{"REREREREREREREREREREREREREREREREREREREREREQ=": "private-network"},
		},
		passphrase,
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
	manifest, err := OpenSealedManifest(root, passphrase)
	if err != nil {
		t.Fatalf("OpenSealedManifest() error = %v", err)
	}
	projection := manifest.SourceProjection()
	if projection.UserAutoApprove == nil || !*projection.UserAutoApprove {
		t.Fatalf("UserAutoApprove = %+v, want true", projection.UserAutoApprove)
	}
	if len(projection.GenesisHashMappings) != 1 {
		t.Fatalf("GenesisHashMappings = %+v", projection.GenesisHashMappings)
	}
}
