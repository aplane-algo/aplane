// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
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
	if err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
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

func TestSealedManifestOmitsOperationalSourceContext(t *testing.T) {
	passphrase := []byte("export-passphrase")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "apb"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "apb", "ADDR.apb"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		passphrase,
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
	manifest, err := OpenSealedManifest(root, passphrase)
	if err != nil {
		t.Fatalf("OpenSealedManifest() error = %v", err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"user_auto_approve", "genesis_hash_mappings", "policy"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("credential manifest contains operational authority %q: %s", forbidden, encoded)
		}
	}
}

// sealCraftedManifest writes a manifest the writer would never produce,
// modelling an attacker who knows the export passphrase. These are the only
// paths that reach the defensive checks in verifyArchiveMembers.
func sealCraftedManifest(t *testing.T, root string, manifest Manifest, passphrase []byte) {
	t.Helper()
	plaintext, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(crafted manifest) error = %v", err)
	}
	sealed, err := crypto.EncryptStandalone(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptStandalone(crafted manifest) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestFileName), sealed, 0o600); err != nil {
		t.Fatalf("WriteFile(crafted manifest) error = %v", err)
	}
}

func TestSealedManifestRejectsCraftedMemberPaths(t *testing.T) {
	passphrase := []byte("export-passphrase")
	base := Manifest{
		Schema:         ManifestSchema,
		SchemaVersion:  ManifestSchemaVersion,
		SourceNodeRole: string(noderole.RoleSigner),
		CreatedAtUnix:  1_700_000_000,
	}

	cases := []struct {
		name    string
		members []ManifestMember
		wantErr string
	}{
		{
			name: "duplicate member",
			members: []ManifestMember{
				{Path: "apb/A.apb", SHA256: strings.Repeat("a", 64), Size: 1},
				{Path: "apb/A.apb", SHA256: strings.Repeat("b", 64), Size: 1},
			},
			wantErr: "twice",
		},
		{
			name:    "traversal path",
			members: []ManifestMember{{Path: "../escape", SHA256: strings.Repeat("a", 64), Size: 1}},
			wantErr: "non-canonical",
		},
		{
			name:    "absolute path",
			members: []ManifestMember{{Path: "/etc/passwd", SHA256: strings.Repeat("a", 64), Size: 1}},
			wantErr: "non-relative",
		},
		{
			name:    "backslash path",
			members: []ManifestMember{{Path: `apb\A.apb`, SHA256: strings.Repeat("a", 64), Size: 1}},
			wantErr: "non-relative",
		},
		{
			name:    "non-canonical path",
			members: []ManifestMember{{Path: "apb/./A.apb", SHA256: strings.Repeat("a", 64), Size: 1}},
			wantErr: "non-canonical",
		},
		{
			name:    "manifest inventories itself",
			members: []ManifestMember{{Path: ManifestFileName, SHA256: strings.Repeat("a", 64), Size: 1}},
			wantErr: "invalid member path",
		},
		{
			name:    "empty path",
			members: []ManifestMember{{Path: "", SHA256: strings.Repeat("a", 64), Size: 1}},
			wantErr: "invalid member path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "apb"), 0o750); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			manifest := base
			manifest.Members = tc.members
			sealCraftedManifest(t, root, manifest, passphrase)

			_, err := OpenSealedManifest(root, passphrase)
			if err == nil {
				t.Fatal("OpenSealedManifest accepted a crafted member list")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("OpenSealedManifest() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestSealedManifestRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	oversized := make([]byte, maxSealedManifestBytes+1)
	if err := os.WriteFile(filepath.Join(root, ManifestFileName), oversized, 0o600); err != nil {
		t.Fatalf("WriteFile(oversized manifest) error = %v", err)
	}
	_, err := OpenSealedManifest(root, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("OpenSealedManifest() error = %v, want size-limit rejection", err)
	}
}

// TestSealedManifestSizeCapMatchesReader proves the writer's bound is on the
// sealed bytes: an archive that seals must always read back. A plaintext-side
// bound would pass here and fail on read, because the envelope base64-encodes
// the ciphertext inside indented JSON.
func TestSealedManifestSizeCapMatchesReader(t *testing.T) {
	passphrase := []byte("export-passphrase")
	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Enough members that the sealed manifest crosses the cap.
	for i := 0; i < 12000; i++ {
		name := fmt.Sprintf("%s%05d.apb", strings.Repeat("A", 45), i)
		if err := os.WriteFile(filepath.Join(keysDir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile(member %d) error = %v", i, err)
		}
	}
	err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		passphrase,
	)
	if err == nil {
		// If it sealed, the reader must accept it — never seal-then-fail.
		if _, readErr := OpenSealedManifest(root, passphrase); readErr != nil {
			t.Fatalf("manifest sealed but cannot be read back: %v", readErr)
		}
		return
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("WriteSealedManifest() error = %v, want a sealed-size refusal", err)
	}
}
