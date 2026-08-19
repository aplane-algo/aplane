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
		{"identity", paths.IdentityDir("default"), identityDir},
		{"metadata", paths.KeystoreMetadataDir("default"), identityDir},
		{"legacy keys", paths.LegacyKeysDir("default"), filepath.Join(identityDir, "keys")},
		{"deleted", paths.DeletedDir("default"), filepath.Join(identityDir, "deleted")},
		{"deleted keys", paths.DeletedKeysDir("default"), filepath.Join(identityDir, "deleted", "keys")},
		{"backups", paths.IdentityBackupsDir("default"), filepath.Join(root, "backups", "default")},
		{"legacy key types", paths.LegacyKeyTypeRecordsDir("default"), filepath.Join(identityDir, "keytypes")},
		{"sentry references", paths.SentryRefsDir("default"), filepath.Join(identityDir, "sentries")},
		{"sentry reference", paths.SentryRefPath("default", "primary"), filepath.Join(identityDir, "sentries", "primary.json")},
		{"node role sidecar", paths.NodeRoleIntegritySidecar("default"), filepath.Join(identityDir, "node.yaml.hmac")},
		{"rotation snapshot", paths.RotationSnapshotPath("default"), filepath.Join(identityDir, "rotation.snapshot.enc")},
		{"rotation baseline", paths.RotationBaselinePath("default"), filepath.Join(identityDir, "rotation.baseline.enc")},
		{"current", paths.CurrentPointerPath("default"), filepath.Join(identityDir, CurrentPointerName)},
		{"generations", paths.GenerationsDir("default"), filepath.Join(identityDir, GenerationsDirName)},
		{"generation", paths.GenerationDir("default", generationID), filepath.Join(identityDir, GenerationsDirName, generationID)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("path = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestNodeRolePaths(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	if got, want := paths.NodeRolePath(), filepath.Join("/tmp/test-keystore", "node.yaml"); got != want {
		t.Fatalf("NodeRolePath() = %q, want %q", got, want)
	}
	wantSidecar := filepath.Join("/tmp/test-keystore", "identities", "default", "node.yaml.hmac")
	if got := paths.NodeRoleIntegritySidecar("default"); got != wantSidecar {
		t.Fatalf("NodeRoleIntegritySidecar() = %q, want %q", got, wantSidecar)
	}
}

func TestRotationPathsAreIdentityScoped(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	identityDir := filepath.Join("/tmp/test-keystore", "identities", "default")
	if got, want := paths.RotationSnapshotPath("default"), filepath.Join(identityDir, "rotation.snapshot.enc"); got != want {
		t.Fatalf("RotationSnapshotPath() = %q, want %q", got, want)
	}
	if got, want := paths.RotationBaselinePath("default"), filepath.Join(identityDir, "rotation.baseline.enc"); got != want {
		t.Fatalf("RotationBaselinePath() = %q, want %q", got, want)
	}
}

func TestKeyTypePathsAreIdentityScoped(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	wantDir := filepath.Join("/tmp/test-keystore", "identities", "default", "keytypes")
	if gotDir := paths.LegacyKeyTypeRecordsDir("default"); gotDir != wantDir {
		t.Fatalf("LegacyKeyTypeRecordsDir() = %q, want %q", gotDir, wantDir)
	}

	if gotFile := paths.LegacyKeyTypeRecord("default", "aplane.ed25519.v1"); gotFile != filepath.Join(wantDir, "aplane.ed25519.v1.json") {
		t.Fatalf("LegacyKeyTypeRecord() = %q", gotFile)
	}
	if gotFile := paths.LegacyKeyTypeTemplate("default", "test.generic-policy.v1"); gotFile != filepath.Join(wantDir, "test.generic-policy.v1.template") {
		t.Fatalf("LegacyKeyTypeTemplate() = %q", gotFile)
	}
}

func TestDeletedPathsAreIdentityScoped(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	identityDir := filepath.Join("/tmp/test-keystore", "identities", "default")
	if got, want := paths.DeletedDir("default"), filepath.Join(identityDir, "deleted"); got != want {
		t.Fatalf("DeletedDir() = %q, want %q", got, want)
	}
	if got, want := paths.DeletedKeysDir("default"), filepath.Join(identityDir, "deleted", "keys"); got != want {
		t.Fatalf("DeletedKeysDir() = %q, want %q", got, want)
	}
	got := paths.DeletedKeyTypeTemplate("default", "test.generic-policy.v1")
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

func TestKeysDirRejectsTraversal(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("KeysDir with traversal identity did not panic")
		}
	}()
	NewPaths("/tmp/test-keystore").LegacyKeysDir("../../etc")
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
			_ = paths.LegacyKeyTypeRecord("default", keyType)
		}()
	}
}
