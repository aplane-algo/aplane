// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestResolveManagedBackupPathScopesToIdentityBackupDir(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	managed := BuildManagedArchivePath(paths, "default", "one")
	resolved, err := ResolveManagedBackupPath(paths, "default", filepath.Base(managed))
	if err != nil {
		t.Fatal(err)
	}
	if resolved != managed {
		t.Fatalf("resolved = %q, want %q", resolved, managed)
	}
	if _, err := ResolveManagedBackupPath(paths, "default", "../escape.tar.gz"); err == nil {
		t.Fatal("ResolveManagedBackupPath accepted traversal")
	}
}

func TestListManagedBackupsSortsArchivesAndIgnoresSymlinks(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.ProductBackupsDir(), 0o770); err != nil {
		t.Fatal(err)
	}
	older := BuildManagedArchivePath(paths, "default", "older")
	newer := BuildManagedArchivePath(paths, "default", "newer")
	if err := os.WriteFile(older, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Unix(100, 0)
	if err := os.Chtimes(older, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(newer, filepath.Join(paths.ProductBackupsDir(), "link.tar.gz")); err != nil {
		t.Fatal(err)
	}
	items, err := ListManagedBackups(paths, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Path != newer || items[1].Path != older {
		t.Fatalf("backups = %+v", items)
	}
}

func TestPreviewRestoreReportsCanonicalCredentialWithoutTemplate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	archive, address := writeCredentialArchiveForBackupTest(t, paths, noderole.RoleSigner)
	preview, err := PreviewRestoreWithNodeRole(
		paths, "default", archive, []byte("export-passphrase"), noderole.RoleSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Keys) != 1 || preview.Keys[0].Address != address {
		t.Fatalf("preview = %+v", preview)
	}
}

func TestRestoreKeyWritesCredentialOnlyAndRequiresOverwrite(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}
	address, payload := testEd25519BackupKeyJSON(t)
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), payload, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	restorer := NewRestorer(paths, "default").WithNodeRole(noderole.RoleSigner)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if _, err := restorer.RestoreKey(keysDir, address, kr, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(active.KeysDir(), address+keys.AccountKeyExtension)); err != nil {
		t.Fatal(err)
	}
	if _, err := restorer.RestoreKey(keysDir, address, kr, []byte("export-passphrase")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second RestoreKey() error = %v", err)
	}
}

func writeCredentialArchiveForBackupTest(t *testing.T, paths storepaths.Paths, role noderole.Role) (string, string) {
	t.Helper()
	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}
	address, payload := testEd25519BackupKeyJSON(t)
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), payload, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := WriteSealedManifest(root, role, time.Unix(1_700_000_000, 0), []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	archive := BuildManagedArchivePath(paths, "default", "credential-test")
	if err := CreateTarGzArchive(root, archive); err != nil {
		t.Fatal(err)
	}
	return archive, address
}

func testSentryComponentBackupKeyJSON(t *testing.T) (string, []byte) {
	t.Helper()
	return keystest.SentryComponentFalcon1024KeyJSON(t, 0xcd)
}

func TestLoadManagedRestoreSetRejectsRoleMismatch(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archive, _ := writeCredentialArchiveForBackupTest(t, paths, noderole.RoleSigner)
	set, err := LoadManagedRestoreSet(paths, "default", archive, nil, []byte("export-passphrase"), noderole.RoleSentry)
	if set != nil {
		set.ZeroSecrets()
	}
	if err == nil || !strings.Contains(err.Error(), "cannot be restored") {
		t.Fatalf("LoadManagedRestoreSet() error = %v", err)
	}
}

func TestCredentialEntryZeroSecrets(t *testing.T) {
	entry := CredentialEntry{KeyJSON: []byte("secret")}
	alias := entry.KeyJSON
	entry.ZeroSecrets()
	for i, value := range alias {
		if value != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
	if entry.KeyJSON != nil {
		t.Fatal("KeyJSON retained after ZeroSecrets")
	}
}

func TestClassifyAndApplyCrossClassCollisionRequiresReplacement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatal(err)
	}
	selector, payload := testEd25519BackupKeyJSON(t)
	entry := CredentialEntry{
		Selector: selector,
		Category: keys.CategoryEd25519,
		KeyType:  "ed25519",
		KeyJSON:  payload,
	}
	defer entry.ZeroSecrets()
	if err := os.WriteFile(filepath.Join(active.KeysDir(), selector+keys.SentryCredentialExtension), []byte("contradictory"), 0o600); err != nil {
		t.Fatal(err)
	}
	kr := cryptotest.Keyring(t, testExportMasterKey)
	classification, err := ClassifyRestoreSet(active, &RestoreSet{Entries: []CredentialEntry{entry}}, kr)
	if err != nil {
		t.Fatal(err)
	}
	if len(classification.Conflicts) != 1 || len(classification.Pending) != 1 {
		t.Fatalf("classification = %+v, want one replaceable class conflict", classification)
	}
	if err := ApplyCredentialEntry(active, entry, kr, false); err == nil {
		t.Fatal("ApplyCredentialEntry accepted cross-class replacement without consent")
	}
	if err := ApplyCredentialEntry(active, entry, kr, true); err != nil {
		t.Fatalf("ApplyCredentialEntry(replace) error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(active.KeysDir(), selector+keys.SentryCredentialExtension)); !os.IsNotExist(err) {
		t.Fatalf("contradictory sentry credential remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(active.KeysDir(), selector+keys.AccountKeyExtension)); err != nil {
		t.Fatalf("canonical account credential missing: %v", err)
	}
}

func TestClassifyRestoreSetReportsReadableDifferentCredential(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatal(err)
	}
	selector, payload := testEd25519BackupKeyJSON(t)
	entry := CredentialEntry{
		Selector: selector,
		Category: keys.CategoryEd25519,
		KeyType:  "ed25519",
		KeyJSON:  payload,
	}
	defer entry.ZeroSecrets()

	destinationPayload, err := keys.ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	destinationPayload.CreatedAt = destinationPayload.CreatedAt.Add(time.Second)
	different, err := keys.MarshalPayload(destinationPayload)
	destinationPayload.ZeroSecrets()
	if err != nil {
		t.Fatal(err)
	}
	destination := entry
	destination.KeyJSON = different
	defer destination.ZeroSecrets()
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if err := ApplyCredentialEntry(active, destination, kr, false); err != nil {
		t.Fatalf("install readable destination credential: %v", err)
	}

	classification, err := ClassifyRestoreSet(active, &RestoreSet{Entries: []CredentialEntry{entry}}, kr)
	if err != nil {
		t.Fatal(err)
	}
	if len(classification.Conflicts) != 1 || len(classification.Pending) != 1 || len(classification.Identical) != 0 {
		t.Fatalf("classification = %+v, want one readable conflict", classification)
	}
	if classification.Conflicts[0].Reason != "existing credential differs from backup" {
		t.Fatalf("conflict reason = %q", classification.Conflicts[0].Reason)
	}
}

func TestLoadManagedRestoreSetRejectsMissingRuntimeProvider(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	payload := keystest.DSALSigKeyJSON(
		t,
		"example.missing-provider-lsig.v1",
		"example.missing-provider.v1",
		[]byte{0x01},
		[]byte{0x02},
		saltedLogicSigBytecodeForTest(),
		saltCounterForTest,
	)
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()
	parsed, err := keys.ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := parsed.Selector()
	parsed.ZeroSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(apbDir, selector+".apb"), payload, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	archive := BuildManagedArchivePath(paths, "default", "missing-provider")
	if err := CreateTarGzArchive(root, archive); err != nil {
		t.Fatal(err)
	}
	set, err := LoadManagedRestoreSet(paths, "default", archive, nil, []byte("export-passphrase"), noderole.RoleSigner)
	if set != nil {
		set.ZeroSecrets()
	}
	if err == nil || !strings.Contains(err.Error(), "is not available") {
		t.Fatalf("LoadManagedRestoreSet() error = %v, want missing runtime provider", err)
	}
	if !ArchiveAuthenticated(err) {
		t.Fatal("missing provider error did not preserve successful archive authentication")
	}
}
