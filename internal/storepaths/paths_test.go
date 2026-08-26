// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

import (
	"path/filepath"
	"testing"
)

func TestTemplateLibraryDirUsesLibraryTemplatesSubdirectory(t *testing.T) {
	got := NewPaths("/tmp/test-keystore").TemplateLibraryDir()
	want := filepath.Join("/tmp/test-keystore", "library", "templates")
	if got != want {
		t.Fatalf("TemplateLibraryDir() = %q, want %q", got, want)
	}
}

func TestProductPathsAreBoundAtConstruction(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "aplane")
	paths := NewPaths(root)
	if got, want := paths.ProductDir(), filepath.Join(root, "identities", "default"); got != want {
		t.Fatalf("ProductDir() = %q, want %q", got, want)
	}
	if got, want := paths.ProductBackupsDir(), filepath.Join(root, "backups", "default"); got != want {
		t.Fatalf("ProductBackupsDir() = %q, want %q", got, want)
	}
}

func TestCanonicalProductStorePathMatrix(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "aplane")
	paths := NewPaths(root)
	identityDir := filepath.Join(root, "identities", "default")
	generationID := "gen-1700000000-0123abcd"

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"identity", paths.ProductDir(), identityDir},
		{"metadata", paths.KeystoreMetadataDir(), identityDir},
		{"legacy keys", paths.LegacyKeysDir(), filepath.Join(identityDir, "keys")},
		{"deleted", paths.DeletedDir(), filepath.Join(identityDir, "deleted")},
		{"deleted keys", paths.DeletedKeysDir(), filepath.Join(identityDir, "deleted", "keys")},
		{"backups", paths.ProductBackupsDir(), filepath.Join(root, "backups", "default")},
		{"legacy key types", paths.LegacyKeyTypeRecordsDir(), filepath.Join(identityDir, "keytypes")},
		{"sentry references", paths.SentryRefsDir(), filepath.Join(identityDir, "sentries")},
		{"sentry reference", paths.SentryRefPath("primary"), filepath.Join(identityDir, "sentries", "primary.json")},
		{"node role sidecar", paths.NodeRoleIntegritySidecar(), filepath.Join(identityDir, "node.yaml.hmac")},
		{"rotation snapshot", paths.RotationSnapshotPath(), filepath.Join(identityDir, "rotation.snapshot.enc")},
		{"rotation baseline", paths.RotationBaselinePath(), filepath.Join(identityDir, "rotation.baseline.enc")},
		{"store root", paths.StoreRootPath(), filepath.Join(identityDir, StoreRootName)},
		{"current", paths.CurrentPointerPath(), filepath.Join(identityDir, CurrentPointerName)},
		{"generations", paths.GenerationsDir(), filepath.Join(identityDir, GenerationsDirName)},
		{"generation", paths.GenerationDir(generationID), filepath.Join(identityDir, GenerationsDirName, generationID)},
		{"quarantine", paths.QuarantineDir(), filepath.Join(identityDir, QuarantineDirName)},
		{
			"quarantined generations",
			paths.QuarantinedGenerationsDir(),
			filepath.Join(identityDir, QuarantineDirName, QuarantinedGenerationsDirName),
		},
		{
			"quarantined generation",
			paths.QuarantinedGenerationDir(generationID),
			filepath.Join(identityDir, QuarantineDirName, QuarantinedGenerationsDirName, generationID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("path = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestGenerationOwnedPathMatrix(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "aplane")
	paths := NewPaths(root)
	generationID := "gen-1700000000-0123abcd"
	gen := paths.GenerationPaths(generationID)
	generationDir := filepath.Join(root, "identities", "default", GenerationsDirName, generationID)

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"keys", gen.KeysDir(), filepath.Join(generationDir, "keys")},
		{"key types", gen.KeyTypeRecordsDir(), filepath.Join(generationDir, "keytypes")},
		{
			"key type record",
			gen.KeyTypeRecord("aplane.ed25519.v1"),
			filepath.Join(generationDir, "keytypes", "aplane.ed25519.v1.json"),
		},
		{
			"key type template",
			gen.KeyTypeTemplate("test.generic-policy.v1"),
			filepath.Join(generationDir, "keytypes", "test.generic-policy.v1.template"),
		},
		{"deleted", gen.DeletedDir(), filepath.Join(generationDir, "deleted")},
		{"deleted keys", gen.DeletedKeysDir(), filepath.Join(generationDir, "deleted", "keys")},
		{"deleted key types", gen.DeletedKeyTypeRecordsDir(), filepath.Join(generationDir, "deleted", "keytypes")},
		{
			"deleted key type template",
			gen.DeletedKeyTypeTemplate("test.generic-policy.v1"),
			filepath.Join(generationDir, "deleted", "keytypes", "test.generic-policy.v1.template"),
		},
		{"policy", gen.PolicyPath(), filepath.Join(generationDir, "policy.yaml")},
		{"policy sidecar", gen.PolicyIntegritySidecar(), filepath.Join(generationDir, "policy.yaml.hmac")},
		{"node role sidecar", gen.NodeRoleIntegritySidecar(), filepath.Join(generationDir, "node.yaml.hmac")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("path = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestQuarantinedGenerationPathRejectsUnsafeID(t *testing.T) {
	paths := NewPaths(t.TempDir())
	for _, generationID := range []string{"", "../generation", "gen-bad", "gen-1-ABCDEF12"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("QuarantinedGenerationDir(%q) did not panic", generationID)
				}
			}()
			_ = paths.QuarantinedGenerationDir(generationID)
		}()
	}
}

func TestNodeRolePaths(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	if got, want := paths.NodeRolePath(), filepath.Join("/tmp/test-keystore", "node.yaml"); got != want {
		t.Fatalf("NodeRolePath() = %q, want %q", got, want)
	}
	wantSidecar := filepath.Join("/tmp/test-keystore", "identities", "default", "node.yaml.hmac")
	if got := paths.NodeRoleIntegritySidecar(); got != wantSidecar {
		t.Fatalf("NodeRoleIntegritySidecar() = %q, want %q", got, wantSidecar)
	}
}

func TestRotationPathsAreWithinProductStore(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	identityDir := filepath.Join("/tmp/test-keystore", "identities", "default")
	if got, want := paths.RotationSnapshotPath(), filepath.Join(identityDir, "rotation.snapshot.enc"); got != want {
		t.Fatalf("RotationSnapshotPath() = %q, want %q", got, want)
	}
	if got, want := paths.RotationBaselinePath(), filepath.Join(identityDir, "rotation.baseline.enc"); got != want {
		t.Fatalf("RotationBaselinePath() = %q, want %q", got, want)
	}
}

func TestKeyTypePathsAreWithinProductStore(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	wantDir := filepath.Join("/tmp/test-keystore", "identities", "default", "keytypes")
	if gotDir := paths.LegacyKeyTypeRecordsDir(); gotDir != wantDir {
		t.Fatalf("LegacyKeyTypeRecordsDir() = %q, want %q", gotDir, wantDir)
	}

	if gotFile := paths.LegacyKeyTypeRecord("aplane.ed25519.v1"); gotFile != filepath.Join(wantDir, "aplane.ed25519.v1.json") {
		t.Fatalf("LegacyKeyTypeRecord() = %q", gotFile)
	}
	if gotFile := paths.LegacyKeyTypeTemplate("test.generic-policy.v1"); gotFile != filepath.Join(wantDir, "test.generic-policy.v1.template") {
		t.Fatalf("LegacyKeyTypeTemplate() = %q", gotFile)
	}
}

func TestDeletedPathsAreWithinProductStore(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	identityDir := filepath.Join("/tmp/test-keystore", "identities", "default")
	if got, want := paths.DeletedDir(), filepath.Join(identityDir, "deleted"); got != want {
		t.Fatalf("DeletedDir() = %q, want %q", got, want)
	}
	if got, want := paths.DeletedKeysDir(), filepath.Join(identityDir, "deleted", "keys"); got != want {
		t.Fatalf("DeletedKeysDir() = %q, want %q", got, want)
	}
	got := paths.DeletedKeyTypeTemplate("test.generic-policy.v1")
	want := filepath.Join(identityDir, "deleted", "keytypes", "test.generic-policy.v1.template")
	if got != want {
		t.Fatalf("DeletedKeyTypeTemplate() = %q, want %q", got, want)
	}
}

func TestValidatePathComponent(t *testing.T) {
	valid := []string{"default", "user-123", "org_tenant", "a"}
	for _, v := range valid {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("validatePathComponent(%q) panicked unexpectedly: %v", v, r)
				}
			}()
			validatePathComponent("test", v)
		}()
	}

	invalid := []string{"", "..", "foo/..", "../etc", "a/b", `a\b`, "foo/bar"}
	for _, v := range invalid {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("validatePathComponent(%q) did not panic", v)
				}
			}()
			validatePathComponent("test", v)
		}()
	}
}

func TestKeyTypePathsRejectUnsafeComponents(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	invalid := []string{"", "Bad-v1", "_bad-v1", "-bad-v1", "bad:name", "bad/name", `bad\name`, "bad\x00name", "../bad", "bad..name"}
	for _, keyType := range invalid {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("KeyTypeRecord(%q) did not panic", keyType)
				}
			}()
			_ = paths.LegacyKeyTypeRecord(keyType)
		}()
	}
}
