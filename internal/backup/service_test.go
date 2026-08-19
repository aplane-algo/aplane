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

func TestCreateAllKeysArchiveUsesPrivateManagedBackupPermissions(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.LegacyKeysDir()); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}

	address, keyJSON := testEd25519BackupKeyJSON(t)
	encryptedKey, err := cryptotest.Keyring(t, testExportMasterKey).Seal(keyJSON, crypto.AccountKeyContext(address))
	if err != nil {
		t.Fatalf("encryptWithTermKey() error = %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, address), encryptedKey, fsutil.StoreFilePerm); err != nil {
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
		cryptotest.Keyring(t, testExportMasterKey),
	)); err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}

	assertStoreDirMode(t, paths.BackupsRootDir())
	assertStoreDirMode(t, paths.ProductBackupsDir())
	assertFileMode(t, archivePath, fsutil.StoreFilePerm)

	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", address+".apb")); err != nil {
		t.Fatalf("extracted backup payload stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy")); !os.IsNotExist(err) {
		t.Fatalf("credential archive must omit policy state, stat error = %v", err)
	}
	manifest, err := OpenSealedManifest(extractDir, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("OpenSealedManifest() error = %v", err)
	}
	if manifest.SourceNodeRole != string(noderole.RoleSigner) {
		t.Fatalf("manifest source node role = %q, want signer", manifest.SourceNodeRole)
	}
	// Every credential archive member is covered by the sealed manifest.
	covered := make(map[string]bool, len(manifest.Members))
	for _, member := range manifest.Members {
		covered[member.Path] = true
	}
	for _, required := range []string{
		"apb/" + address + ".apb",
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
	if err := fsutil.MkdirAll(paths.LegacyKeysDir()); err != nil {
		t.Fatal(err)
	}
	selector, keyJSON := testSentryComponentBackupKeyJSON(t)
	encrypted, err := cryptotest.Keyring(t, testExportMasterKey).Seal(keyJSON, crypto.SentryCredentialContext(selector))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apkeys.SentryCredentialFilePath(paths, selector), encrypted, fsutil.StoreFilePerm); err != nil {
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
		cryptotest.Keyring(t, testExportMasterKey),
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
	kr *crypto.Keyring,
) CreateKeysArchiveRequest {
	_ = role
	return CreateKeysArchiveRequest{
		Paths:            paths,
		IdentityID:       identityID,
		ArchivePath:      archivePath,
		Addresses:        addresses,
		Keyring:          kr,
		ExportPassphrase: []byte("export-passphrase"),
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
	if got := info.Mode() & os.ModePerm; got != 0700 {
		t.Fatalf("mode(%s) = %o, want 0700", path, got)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		t.Fatalf("mode(%s) unexpectedly has setgid bit: %v", path, info.Mode())
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

// A complete archive never silently omits a damaged managed credential.
func TestCreateAllKeysArchiveFailsIfAnyCredentialIsInvalid(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	const identityID = "default"
	const badAddress = "BADCANONICALKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.LegacyKeysDir()); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}

	address, keyJSON := testEd25519BackupKeyJSON(t)
	encryptedKey, err := cryptotest.Keyring(t, testExportMasterKey).Seal(keyJSON, crypto.AccountKeyContext(address))
	if err != nil {
		t.Fatalf("encryptWithTermKey() error = %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, address), encryptedKey, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	// Decryptable but non-canonical payload (pre-cutover shape with alias field).
	encryptedBad, err := cryptotest.Keyring(t, testExportMasterKey).Seal(
		[]byte(`{"key_type":"ed25519","params":{"a":"b"}}`),
		crypto.AccountKeyContext(badAddress),
	)
	if err != nil {
		t.Fatalf("Seal(bad) error = %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, badAddress), encryptedBad, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(bad key) error = %v", err)
	}

	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := policy.SaveStoredConfigWithKeyring(paths.Root(), identityID, &policy.StoredConfig{}, cryptotest.Keyring(t, testExportMasterKey), timeForBackupTest()); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260710-010203")
	_, err = CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		archivePath,
		nil,
		noderole.RoleSigner,
		cryptotest.Keyring(t, testExportMasterKey),
	))
	if err == nil || !strings.Contains(err.Error(), "failed to export "+badAddress) {
		t.Fatalf("CreateKeysArchive() error = %v, want damaged-credential failure", err)
	}

	// Explicitly selecting the invalid key still fails closed.
	selectedPath := BuildManagedArchivePath(paths, identityID, "20260710-020304")
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(
		paths,
		identityID,
		selectedPath,
		[]string{badAddress},
		noderole.RoleSigner,
		cryptotest.Keyring(t, testExportMasterKey),
	)); err == nil {
		t.Fatal("CreateKeysArchive(selected invalid key) should fail closed")
	}
}

func TestCreateAllKeysArchiveFailsForInvalidOnlyCredential(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if err := fsutil.MkdirAll(paths.LegacyKeysDir()); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	const badAddress = "ONLYINVALIDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	encryptedBad, err := cryptotest.Keyring(t, testExportMasterKey).Seal([]byte(`{"key_type":"ed25519"}`), crypto.AccountKeyContext(badAddress))
	if err != nil {
		t.Fatalf("Seal(bad) error = %v", err)
	}
	badFile := apkeys.AccountKeyFilePath(paths, badAddress)
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
		cryptotest.Keyring(t, testExportMasterKey),
	))
	if err == nil || !strings.Contains(err.Error(), "failed to export "+badAddress) {
		t.Fatalf("CreateKeysArchive() error = %v, want damaged-credential failure", err)
	}
}

// Infrastructure failures also abort the complete archive.
func TestExportAllKeysStillAbortsOnDecryptFailure(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	srcDir := active.KeysDir()
	corruptFile := apkeys.AccountKeyFilePath(paths, "UNDECRYPTABLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err := os.WriteFile(corruptFile, []byte("not encrypted data"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(corrupt) error = %v", err)
	}

	_, err = ExportAllKeys(paths, identityID, srcDir, t.TempDir(), cryptotest.Keyring(t, testExportMasterKey), []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "failed to export") {
		t.Fatalf("ExportAllKeys() error = %v, want decrypt-failure abort", err)
	}
}
