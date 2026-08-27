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
		{"backups", paths.ProductBackupsDir(), filepath.Join(root, "backups", "default")},
		{"sentry references", paths.SentryRefsDir(), filepath.Join(identityDir, "sentries")},
		{"sentry reference", paths.SentryRefPath("primary"), filepath.Join(identityDir, "sentries", "primary.json")},
		{"store root", paths.StoreRootPath(), filepath.Join(identityDir, StoreRootName)},
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
	active := paths.GenerationPaths("gen-1-0123abcd")
	invalid := []string{"", "Bad-v1", "_bad-v1", "-bad-v1", "bad:name", "bad/name", `bad\name`, "bad\x00name", "../bad", "bad..name"}
	for _, keyType := range invalid {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("KeyTypeRecord(%q) did not panic", keyType)
				}
			}()
			_ = active.KeyTypeRecord(keyType)
		}()
	}
}

func TestBindActiveRejectsQuarantineCapability(t *testing.T) {
	paths := NewPaths(t.TempDir())
	id := "gen-1-0123abcd"
	quarantined := StagedGenerationPaths(id, paths.QuarantinedGenerationDir(id))
	if _, err := paths.BindActive(quarantined); err == nil {
		t.Fatal("BindActive() accepted a quarantine-rooted generation capability")
	}
}
