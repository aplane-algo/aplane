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

func TestKeyTypePathsAreIdentityScoped(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	wantDir := filepath.Join("/tmp/test-keystore", "identities", "default", "keytypes")
	if gotDir := paths.KeyTypeRecordsDir("default"); gotDir != wantDir {
		t.Fatalf("KeyTypeRecordsDir() = %q, want %q", gotDir, wantDir)
	}

	if gotFile := paths.KeyTypeRecord("default", "aplane.ed25519.v1"); gotFile != filepath.Join(wantDir, "aplane.ed25519.v1.json") {
		t.Fatalf("KeyTypeRecord() = %q", gotFile)
	}
	if gotFile := paths.KeyTypeTemplate("default", "test.generic-policy.v1"); gotFile != filepath.Join(wantDir, "test.generic-policy.v1.template") {
		t.Fatalf("KeyTypeTemplate() = %q", gotFile)
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
	NewPaths("/tmp/test-keystore").KeysDir("../../etc")
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
			_ = paths.KeyTypeRecord("default", keyType)
		}()
	}
}
