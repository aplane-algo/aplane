// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storemigrate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const testIdentity = "default"

var testNow = time.Unix(1_753_600_000, 0)

// legacyStoreFixture builds a v2 flat store with credentials and key-type
// state.
func legacyStoreFixture(t *testing.T) storepaths.Paths {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	if _, masterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(testIdentity), []byte("migrate-test")); err != nil {
		t.Fatalf("CreateKeystoreMetadata: %v", err)
	} else {
		crypto.ZeroBytes(masterKey)
	}
	for dir, files := range map[string]map[string]string{
		paths.KeysDir(testIdentity):           {"ADDR1.key": "credential-1", "WIT1.sen": "sentry-1"},
		paths.KeyTypeRecordsDir(testIdentity): {"ed25519.json": "{}"},
	} {
		if err := os.MkdirAll(dir, 0o770); err != nil {
			t.Fatalf("MkdirAll(%s): %v", dir, err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o660); err != nil {
				t.Fatalf("WriteFile(%s): %v", name, err)
			}
		}
	}
	return paths
}

func assertMigrated(t *testing.T, paths storepaths.Paths, wantKeys map[string]string) {
	t.Helper()
	gen, err := genstore.Resolve(paths, testIdentity)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if err := genstore.ValidateCurrent(gen); err != nil {
		t.Fatalf("ValidateCurrent() error = %v", err)
	}
	for name, content := range wantKeys {
		data, err := os.ReadFile(filepath.Join(gen.KeysDir(), name))
		if err != nil || string(data) != content {
			t.Fatalf("migrated key %s = %q, %v; want %q", name, data, err, content)
		}
	}
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(testIdentity))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	if meta.Version != crypto.GenerationalKeystoreMetadataVersion || meta.Layout != crypto.KeystoreLayoutGenerationsV1 {
		t.Fatalf("metadata = v%d layout %q, want v%d %q",
			meta.Version, meta.Layout, crypto.GenerationalKeystoreMetadataVersion, crypto.KeystoreLayoutGenerationsV1)
	}
	if _, err := os.Lstat(paths.KeysDir(testIdentity)); !os.IsNotExist(err) {
		t.Fatalf("legacy keys/ still present after migration: %v", err)
	}
}

func TestMigrateConvertsLegacyStore(t *testing.T) {
	paths := legacyStoreFixture(t)

	result, err := Migrate(paths, testIdentity, testNow)
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result.AlreadyMigrated || result.ResumedAfterCrash {
		t.Fatalf("result = %+v, want fresh migration", result)
	}
	assertMigrated(t, paths, map[string]string{"ADDR1.key": "credential-1", "WIT1.sen": "sentry-1"})

	// The legacy namespaces were retired, not deleted: the rollback window.
	if result.RetiredDir == "" {
		t.Fatal("no retire directory reported")
	}
	data, err := os.ReadFile(filepath.Join(result.RetiredDir, "keys", "ADDR1.key"))
	if err != nil || string(data) != "credential-1" {
		t.Fatalf("retired copy = %q, %v", data, err)
	}
	// The downgrade backup exists and still says v2.
	backup, err := os.ReadFile(filepath.Join(paths.IdentityDir(testIdentity), ".keystore.premigration"))
	if err != nil || !strings.Contains(string(backup), `"version": 2`) {
		t.Fatalf("downgrade backup = %v, %q", err, backup)
	}

	// Re-running on the migrated store is a validated no-op.
	again, err := Migrate(paths, testIdentity, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("Migrate(again) error = %v", err)
	}
	if !again.AlreadyMigrated || again.GenerationID != result.GenerationID {
		t.Fatalf("second run = %+v, want validated no-op on %s", again, result.GenerationID)
	}
}

func TestMigrateRefusesIncompleteActivation(t *testing.T) {
	paths := legacyStoreFixture(t)
	marker := paths.RecoveredActivationDir(testIdentity, "0123456789abcdef0123456789abcdef")
	if err := os.MkdirAll(marker, 0o770); err != nil {
		t.Fatalf("MkdirAll(marker): %v", err)
	}
	if _, err := Migrate(paths, testIdentity, testNow); err == nil ||
		!strings.Contains(err.Error(), "incomplete activation") {
		t.Fatalf("Migrate() error = %v, want incomplete-activation refusal", err)
	}
	// Nothing was touched.
	if generational, _ := genstore.IsGenerational(paths, testIdentity); generational {
		t.Fatal("refused migration still flipped the store")
	}
}

func TestMigrateRefusesRotationArtifacts(t *testing.T) {
	paths := legacyStoreFixture(t)
	if err := os.WriteFile(filepath.Join(paths.KeysDir(testIdentity), "ADDR1.key.new"), []byte("x"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Migrate(paths, testIdentity, testNow); err == nil ||
		!strings.Contains(err.Error(), "rotation artifact") {
		t.Fatalf("Migrate() error = %v, want rotation-artifact refusal", err)
	}
}

func TestMigrateRefusesUninitializedStore(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := Migrate(paths, testIdentity, testNow); err == nil ||
		!strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("Migrate() error = %v, want not-initialized refusal", err)
	}
}

// TestMigrateCrashMatrix interrupts the migration at every durability
// boundary and proves a retry completes it, with the store never resolving
// to a mixture of layouts.
func TestMigrateCrashMatrix(t *testing.T) {
	crashPoints := []struct {
		name string
		op   fsutil.HookOp
		base string
	}{
		{"before-pointer-write", fsutil.OpFileSync, storepaths.CurrentPointerName},
		{"before-pointer-rename", fsutil.OpRename, storepaths.CurrentPointerName},
		{"before-version-backup", fsutil.OpFileSync, ".keystore.premigration"},
		{"before-version-bump", fsutil.OpRename, ".keystore"},
	}
	for _, crash := range crashPoints {
		t.Run(crash.name, func(t *testing.T) {
			paths := legacyStoreFixture(t)

			injected := errors.New("simulated crash: " + crash.name)
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == crash.op && filepath.Base(path) == crash.base {
					return injected
				}
				return nil
			}
			_, err := Migrate(paths, testIdentity, testNow)
			fsutil.TestHook = nil
			if !errors.Is(err, injected) {
				t.Fatalf("Migrate() error = %v, want injected crash", err)
			}

			// Whatever the interruption point, the store is in exactly one
			// readable state: still legacy (pointer never landed) or
			// generational (pointer landed, bump pending).
			generational, genErr := genstore.IsGenerational(paths, testIdentity)
			if genErr != nil {
				t.Fatalf("IsGenerational() error = %v", genErr)
			}
			if !generational {
				if _, err := os.Lstat(filepath.Join(paths.KeysDir(testIdentity), "ADDR1.key")); err != nil {
					t.Fatalf("legacy store damaged by interrupted migration: %v", err)
				}
			}

			// Retry finishes the migration to the same end state.
			result, err := Migrate(paths, testIdentity, testNow.Add(time.Minute))
			if err != nil {
				t.Fatalf("Migrate(retry) error = %v", err)
			}
			if generational && !result.ResumedAfterCrash && !result.AlreadyMigrated {
				t.Fatalf("retry after pointer flip = %+v, want resumed/no-op", result)
			}
			assertMigrated(t, paths, map[string]string{"ADDR1.key": "credential-1", "WIT1.sen": "sentry-1"})
		})
	}
}

// TestMigrateV1KeystorePersistsLegacyKDFParams proves a version-1 keystore
// (no persisted KDF parameters) migrates cleanly: the v3 record carries the
// frozen legacy constants explicitly, so derivation is unchanged and the
// bump validates.
func TestMigrateV1KeystorePersistsLegacyKDFParams(t *testing.T) {
	paths := legacyStoreFixture(t)
	keystorePath := filepath.Join(paths.IdentityDir(testIdentity), ".keystore")
	data, err := os.ReadFile(keystorePath)
	if err != nil {
		t.Fatalf("read keystore: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("unmarshal keystore: %v", err)
	}
	meta["version"] = 1
	delete(meta, "kdf_time")
	delete(meta, "kdf_memory")
	delete(meta, "kdf_threads")
	rewritten, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal keystore: %v", err)
	}
	if err := os.WriteFile(keystorePath, rewritten, 0o600); err != nil {
		t.Fatalf("rewrite keystore: %v", err)
	}

	result, err := Migrate(paths, testIdentity, testNow)
	if err != nil {
		t.Fatalf("Migrate(v1) error = %v", err)
	}
	if result.AlreadyMigrated || result.ResumedAfterCrash {
		t.Fatalf("result = %+v, want fresh migration", result)
	}
	migrated, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(testIdentity))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	if !migrated.IsGenerationalLayout() {
		t.Fatalf("metadata = v%d layout %q", migrated.Version, migrated.Layout)
	}
	if migrated.KDFTime == 0 || migrated.KDFMemory == 0 || migrated.KDFThreads == 0 {
		t.Fatalf("legacy KDF parameters not persisted: %+v", migrated)
	}
}
