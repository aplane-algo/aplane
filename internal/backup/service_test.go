// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCreateAllKeysArchiveUsesGroupAccessibleManagedBackupPermissions(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}

	address, keyJSON := testEd25519BackupKeyJSON(t)
	encryptedKey, err := crypto.EncryptWithTermKey(
		keyJSON, testExportMasterKey, crypto.FirstTerm, crypto.AccountKeyContext(address),
	)
	if err != nil {
		t.Fatalf("EncryptWithTermKey() error = %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, identityID, address), encryptedKey, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := policy.SaveStoredConfigWithKeyring(paths.Root(), identityID, &policy.StoredConfig{}, cryptotest.Keyring(t, testExportMasterKey), timeForBackupTest()); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260428-010203")
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		archivePath,
		nil,
		noderole.RoleSigner,
	)); err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}

	assertStoreDirMode(t, paths.BackupsRootDir())
	assertStoreDirMode(t, paths.IdentityBackupsDir(identityID))
	assertFileMode(t, archivePath, fsutil.StoreFilePerm)

	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", address+".apb")); err != nil {
		t.Fatalf("extracted backup payload stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy", "policy.yaml")); err != nil {
		t.Fatalf("extracted policy.yaml stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy", "policy.yaml.hmac")); err != nil {
		t.Fatalf("extracted policy.yaml.hmac stat error = %v", err)
	}
	manifest, err := OpenSealedManifest(extractDir, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("OpenSealedManifest() error = %v", err)
	}
	if manifest.SourceNodeRole != string(noderole.RoleSigner) {
		t.Fatalf("manifest source node role = %q, want signer", manifest.SourceNodeRole)
	}
	projection := manifest.SourceProjection()
	if projection.UserAutoApprove == nil || *projection.UserAutoApprove {
		t.Fatalf("source settings = %+v, want manual signer context", projection)
	}
	// Every archive member the writer produced is covered by the manifest,
	// including the policy snapshot and the README.
	covered := make(map[string]bool, len(manifest.Members))
	for _, member := range manifest.Members {
		covered[member.Path] = true
	}
	for _, required := range []string{
		"apb/" + address + ".apb",
		"policy/policy.yaml",
		"policy/policy.yaml.hmac",
		"README.md",
	} {
		if !covered[required] {
			t.Fatalf("archive member %q is not covered by the sealed manifest: %+v", required, manifest.Members)
		}
	}
}

func TestCreateAllKeysArchiveExportsSentryCredential(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatal(err)
	}
	selector, keyJSON := testSentryComponentBackupKeyJSON(t)
	encrypted, err := crypto.EncryptWithTermKey(
		keyJSON, testExportMasterKey, crypto.FirstTerm, crypto.SentryCredentialContext(selector),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apkeys.SentryCredentialFilePath(paths, identityID, selector), encrypted, fsutil.StoreFilePerm); err != nil {
		t.Fatal(err)
	}
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSentry, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	if err := policy.SaveStoredSentryConfigWithKeyring(paths.Root(), identityID, &policy.StoredConfig{}, cryptotest.Keyring(t, testExportMasterKey), timeForBackupTest()); err != nil {
		t.Fatal(err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260721-010203")
	result, err := CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		archivePath,
		nil,
		noderole.RoleSentry,
	))
	if err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	if result.KeyCount != 1 || len(result.Addresses) != 1 || result.Addresses[0] != selector {
		t.Fatalf("archive result = %#v, want sentry witness %s", result, selector)
	}
	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", selector+".apb")); err != nil {
		t.Fatalf("sentry witness .apb missing: %v", err)
	}
}

func timeForBackupTest() time.Time {
	return time.Unix(1700000000, 0)
}

func testCreateKeysArchiveRequest(
	paths storepaths.Paths,
	identityID, archivePath string,
	addresses []string,
	role noderole.Role,
) CreateKeysArchiveRequest {
	var userAutoApprove *bool
	if role == noderole.RoleSigner {
		value := false
		userAutoApprove = &value
	}
	return CreateKeysArchiveRequest{
		Paths:            paths,
		IdentityID:       identityID,
		ArchivePath:      archivePath,
		Addresses:        addresses,
		MasterKey:        testExportMasterKey,
		ExportPassphrase: []byte("export-passphrase"),
		SourceSettings: SourceSettingsSnapshot{
			UserAutoApprove: userAutoApprove,
		},
	}
}

func assertStoreDirMode(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
	if got := info.Mode() & os.ModePerm; got != 0770 {
		t.Fatalf("mode(%s) = %o, want 0770", path, got)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("mode(%s) missing setgid bit: %v", path, info.Mode())
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode() & os.ModePerm; got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}

// TestCreateAllKeysArchiveSkipsInvalidPayloadsAndReports pins the skip-and-report
// contract: an all-keys backup excludes a key whose decrypted payload fails
// canonical validation, reports it in ArchiveResult.Skipped, and still backs up
// the healthy keys. Explicit address selection keeps failing closed.
func TestCreateAllKeysArchiveSkipsInvalidPayloadsAndReports(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	const identityID = "default"
	const badAddress = "BADCANONICALKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}

	address, keyJSON := testEd25519BackupKeyJSON(t)
	encryptedKey, err := crypto.EncryptWithTermKey(
		keyJSON, testExportMasterKey, crypto.FirstTerm, crypto.AccountKeyContext(address),
	)
	if err != nil {
		t.Fatalf("EncryptWithTermKey() error = %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, identityID, address), encryptedKey, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	// Decryptable but non-canonical payload (pre-cutover shape with alias field).
	encryptedBad, err := crypto.EncryptWithTermKey(
		[]byte(`{"key_type":"ed25519","params":{"a":"b"}}`), testExportMasterKey,
		crypto.FirstTerm, crypto.AccountKeyContext(badAddress),
	)
	if err != nil {
		t.Fatalf("EncryptWithTermKey(bad) error = %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, identityID, badAddress), encryptedBad, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(bad key) error = %v", err)
	}

	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := policy.SaveStoredConfigWithKeyring(paths.Root(), identityID, &policy.StoredConfig{}, cryptotest.Keyring(t, testExportMasterKey), timeForBackupTest()); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260710-010203")
	result, err := CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		archivePath,
		nil,
		noderole.RoleSigner,
	))
	if err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	if result.KeyCount != 1 || len(result.Addresses) != 1 || result.Addresses[0] != address {
		t.Fatalf("exported = %#v (count %d), want only %s", result.Addresses, result.KeyCount, address)
	}
	reason, ok := result.Skipped[badAddress]
	if !ok {
		t.Fatalf("Skipped = %#v, want entry for %s", result.Skipped, badAddress)
	}
	if !strings.Contains(reason, "incompatible key file format") {
		t.Fatalf("skip reason = %q, want canonical-format rejection", reason)
	}

	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", address+".apb")); err != nil {
		t.Fatalf("healthy key missing from archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", badAddress+".apb")); !os.IsNotExist(err) {
		t.Fatalf("invalid key must not be in archive, stat err = %v", err)
	}

	// Explicitly selecting the invalid key still fails closed.
	selectedPath := BuildManagedArchivePath(paths, identityID, "20260710-020304")
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		selectedPath,
		[]string{badAddress},
		noderole.RoleSigner,
	)); err == nil {
		t.Fatal("CreateKeysArchive(selected invalid key) should fail closed")
	}
}

// TestCreateAllKeysArchiveFailsWhenNoKeyIsExportable pins that skip-and-report
// never silently produces an empty backup.
func TestCreateAllKeysArchiveFailsWhenNoKeyIsExportable(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	const badAddress = "ONLYINVALIDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	encryptedBad, err := crypto.EncryptWithTermKey(
		[]byte(`{"key_type":"ed25519"}`), testExportMasterKey,
		crypto.FirstTerm, crypto.AccountKeyContext(badAddress),
	)
	if err != nil {
		t.Fatalf("EncryptWithTermKey(bad) error = %v", err)
	}
	badFile := apkeys.AccountKeyFilePath(paths, identityID, badAddress)
	if err := os.WriteFile(badFile, encryptedBad, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(bad key) error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260710-030405")
	_, err = CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		archivePath,
		nil,
		noderole.RoleSigner,
	))
	if err == nil || !strings.Contains(err.Error(), "no exportable keys") {
		t.Fatalf("CreateKeysArchive() error = %v, want no-exportable-keys failure", err)
	}
}

// TestExportAllKeysStillAbortsOnDecryptFailure pins the skip boundary: only
// canonical-payload rejections are skipped; infrastructure failures abort.
func TestExportAllKeysStillAbortsOnDecryptFailure(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	srcDir := active.KeysDir()
	corruptFile := apkeys.AccountKeyFilePath(paths, identityID, "UNDECRYPTABLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err := os.WriteFile(corruptFile, []byte("not encrypted data"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(corrupt) error = %v", err)
	}

	_, _, err = ExportAllKeys(paths, identityID, srcDir, t.TempDir(), testExportMasterKey, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "failed to export") {
		t.Fatalf("ExportAllKeys() error = %v, want decrypt-failure abort", err)
	}
}
