// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

import (
	"path/filepath"
	"strings"
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

func TestRecoveredPathsAreIdentityScoped(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	restoreID := "0123456789abcdef0123456789abcdef"
	wantRoot := filepath.Join("/tmp/test-keystore", "identities", "default", "recovered")
	wantBatch := filepath.Join(wantRoot, restoreID)
	if got := paths.RecoveredRootDir("default"); got != wantRoot {
		t.Fatalf("RecoveredRootDir() = %q, want %q", got, wantRoot)
	}
	if got := paths.RecoveredBatchDir("default", restoreID); got != wantBatch {
		t.Fatalf("RecoveredBatchDir() = %q, want %q", got, wantBatch)
	}
	if got := paths.RecoveredBatchEntriesDir("default", restoreID); got != filepath.Join(wantBatch, "entries") {
		t.Fatalf("RecoveredBatchEntriesDir() = %q", got)
	}
	if got := paths.RecoveredBatchMetadataPath("default", restoreID); got != filepath.Join(wantBatch, "batch.enc") {
		t.Fatalf("RecoveredBatchMetadataPath() = %q", got)
	}
}

func TestRecoveredBatchPathsRejectInvalidRestoreIDs(t *testing.T) {
	paths := NewPaths("/tmp/test-keystore")
	valid := "0123456789abcdef0123456789abcdef"
	for _, restoreID := range []string{"", "batch", "tmp.bak", strings.ToUpper(valid), "../" + valid, valid + "00"} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("RecoveredBatchDir(%q) did not panic", restoreID)
				}
			}()
			_ = paths.RecoveredBatchDir("default", restoreID)
		}()
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
