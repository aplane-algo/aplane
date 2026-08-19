// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

const saltCounterForTest byte = 5

func saltedLogicSigBytecodeForTest() []byte {
	return []byte{0x26, 0x01, 0x01, saltCounterForTest, 0x81, 0x01}
}

func TestCmdRebuildRejectsExistingIdentityBeforePrompt(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	oldReader := stdinReader
	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	stdinReader = nil
	defer func() {
		dataDirectory = oldDataDirectory
		stdinReader = oldReader
	}()

	if err := os.MkdirAll(keystorePaths().ProductDir(), 0o755); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}

	err := withTestStdin("", func() error {
		return cmdRebuild([]string{filepath.Join(t.TempDir(), "missing.tar.gz")})
	})
	if err == nil {
		t.Fatal("cmdRebuild() error = nil, want existing identity refusal")
	}
	if !strings.Contains(err.Error(), "rebuild requires a missing identity directory") {
		t.Fatalf("cmdRebuild() error = %v, want missing identity rule", err)
	}
}

func TestCmdRebuildAcceptsTarballForMissingIdentity(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	oldReader := stdinReader
	dataDirectory = t.TempDir()
	stdinReader = nil
	t.Setenv("APSIGNER_PASSPHRASE", "")
	defer func() {
		dataDirectory = oldDataDirectory
		stdinReader = oldReader
	}()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	if err := backup.WriteReadme(backupRoot); err != nil {
		t.Fatalf("WriteReadme() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "rebuild.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\nnew-store-passphrase\nnew-store-passphrase\n", func() error {
		return cmdRebuild([]string{archivePath, "--address", address})
	}); err != nil {
		t.Fatalf("cmdRebuild() error = %v", err)
	}
	if !apcrypto.KeyringExistsIn(keystorePaths().KeystoreMetadataDir()) {
		t.Fatal("keystore metadata missing after rebuild")
	}
	if _, err := os.Stat(apkeys.AccountKeyFilePath(keystorePaths(), address)); err != nil {
		t.Fatalf("rebuilt key file missing: %v", err)
	}
	kr, err := apcrypto.OpenKeyringStore(keystorePaths().KeystoreMetadataDir(), []byte("new-store-passphrase"))
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()
	role, err := noderole.LoadAndVerifyWithKeyring(keystorePaths(), productIdentityID(), kr)
	if err != nil {
		t.Fatalf("LoadAndVerifyWithKeyring() error = %v", err)
	}
	if role.Role != noderole.RoleSigner {
		t.Fatalf("rebuilt node role = %q, want signer", role.Role)
	}
}

func TestCmdRebuildRoleOverrideRestoresSentryBackup(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	oldReader := stdinReader
	dataDirectory = t.TempDir()
	stdinReader = nil
	t.Setenv("APSIGNER_PASSPHRASE", "")
	defer func() {
		dataDirectory = oldDataDirectory
		stdinReader = oldReader
	}()

	backupRoot := t.TempDir()
	componentKey, keyJSON := testSentryComponentKeyJSONForApstore(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), componentKey, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	if err := backup.WriteReadme(backupRoot); err != nil {
		t.Fatalf("WriteReadme() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "sentry-rebuild.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSentry)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\nnew-store-passphrase\nnew-store-passphrase\n", func() error {
		return cmdRebuild([]string{archivePath, "--role", "sentry", "--address", componentKey})
	}); err != nil {
		t.Fatalf("cmdRebuild() error = %v", err)
	}

	kr, err := apcrypto.OpenKeyringStore(keystorePaths().KeystoreMetadataDir(), []byte("new-store-passphrase"))
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()
	role, err := noderole.LoadAndVerifyWithKeyring(keystorePaths(), productIdentityID(), kr)
	if err != nil {
		t.Fatalf("LoadAndVerifyWithKeyring() error = %v", err)
	}
	if role.Role != noderole.RoleSentry {
		t.Fatalf("rebuilt node role = %q, want sentry", role.Role)
	}
	if _, err := os.Stat(apkeys.SentryCredentialFilePath(keystorePaths(), componentKey)); err != nil {
		t.Fatalf("rebuilt sentry key file missing: %v", err)
	}
	env, ok, err := apkeys.ReadWitnessPublicMetadata(keystorePaths(), componentKey)
	if err != nil {
		t.Fatalf("ReadWitnessPublicMetadata() error = %v", err)
	}
	if !ok {
		t.Fatal("ReadWitnessPublicMetadata() ok = false, want restored sidecar")
	}
	if env.WitnessKeyID != componentKey {
		t.Fatalf("ComponentKey = %q, want %q", env.WitnessKeyID, componentKey)
	}
}

func TestSelectRebuildNodeRoleExplicitOverridesManifest(t *testing.T) {
	root := t.TempDir()
	passphrase := []byte("export-passphrase")
	if err := backup.WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(100, 0),
		passphrase,
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}

	role, err := selectRebuildNodeRole(root, passphrase, noderole.RoleSentry, true)
	if err != nil {
		t.Fatalf("selectRebuildNodeRole() error = %v", err)
	}
	if role != noderole.RoleSentry {
		t.Fatalf("selectRebuildNodeRole() role = %q, want sentry", role)
	}
}

func TestSelectRebuildNodeRoleUsesSealedManifestRole(t *testing.T) {
	root := t.TempDir()
	passphrase := []byte("export-passphrase")
	if err := backup.WriteSealedManifest(
		root,
		noderole.RoleSentry,
		time.Unix(100, 0),
		passphrase,
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}

	role, err := selectRebuildNodeRole(root, passphrase, "", false)
	if err != nil {
		t.Fatalf("selectRebuildNodeRole() error = %v", err)
	}
	if role != noderole.RoleSentry {
		t.Fatalf("selectRebuildNodeRole() role = %q, want sentry from the sealed manifest", role)
	}
}

// TestSelectRebuildNodeRoleRejectsUnauthenticatedArchive proves the role
// default can no longer be taken from an archive that fails authentication.
func TestSelectRebuildNodeRoleRejectsUnauthenticatedArchive(t *testing.T) {
	if _, err := selectRebuildNodeRole(t.TempDir(), []byte("export-passphrase"), "", false); err == nil {
		t.Fatal("selectRebuildNodeRole accepted an archive with no sealed manifest")
	}
}

func TestCmdRebuildRejectsInvalidRoleBeforePrompt(t *testing.T) {
	err := cmdRebuild([]string{"backup.tar.gz", "--role", "dual"})
	if err == nil {
		t.Fatal("cmdRebuild() error = nil, want invalid role")
	}
	if !strings.Contains(err.Error(), "invalid rebuild role") {
		t.Fatalf("cmdRebuild() error = %v, want invalid rebuild role", err)
	}
}

func TestRestoreKeyRejectsLegacyEnvelopeVersion1Backup(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	address, _ := testEd25519KeyJSON(t)

	// Written as a literal: envelope_version 1 is the retired master-key
	// format that this release can no longer produce, and rejecting it is
	// what this test is about.
	legacy := []byte(`{"envelope_version":1,"nonce":"","ciphertext":""}`)
	if err := os.WriteFile(filepath.Join(backupDir, address+".apb"), legacy, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	keyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, bytes32(0x33)), []byte("unused"))
	if err == nil {
		t.Fatal("restoreKey() error = nil, want legacy envelope rejection")
	}
	if keyType != "" {
		t.Fatalf("restoreKey() keyType = %q, want empty on failure", keyType)
	}
	if !strings.Contains(err.Error(), "legacy format") {
		t.Fatalf("restoreKey() error = %v, want legacy format rejection", err)
	}
}

func TestRestoreKeyRejectsUnsupportedEnvelopeVersion(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	address, _ := testEd25519KeyJSON(t)

	unsupported := []byte(`{"envelope_version":3,"nonce":"","ciphertext":""}`)
	if err := os.WriteFile(filepath.Join(backupDir, address+".apb"), unsupported, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	keyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, bytes32(0x44)), []byte("unused"))
	if err == nil {
		t.Fatal("restoreKey() error = nil, want unsupported envelope rejection")
	}
	if keyType != "" {
		t.Fatalf("restoreKey() keyType = %q, want empty on failure", keyType)
	}
	if !strings.Contains(err.Error(), "unsupported envelope_version: 3") {
		t.Fatalf("restoreKey() error = %v, want unsupported envelope rejection", err)
	}
}

func TestCmdVerifyAcceptsTarball(t *testing.T) {
	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	if err := backup.WriteReadme(backupRoot); err != nil {
		t.Fatalf("WriteReadme() error = %v", err)
	}

	archivePath := filepath.Join(t.TempDir(), "verify.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdVerify(archivePath)
	}); err != nil {
		t.Fatalf("cmdVerify() error = %v", err)
	}
}

func TestCmdVerifyFailsWhenAnyCredentialIsInvalid(t *testing.T) {
	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := os.WriteFile(filepath.Join(backupRoot, "apb", address+".apb"), []byte("damaged"), 0o600); err != nil {
		t.Fatalf("damage backup credential: %v", err)
	}

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdVerify(backupRoot)
	})
	if err == nil {
		t.Fatal("cmdVerify() error = nil, want fatal credential verification failure")
	}
	var coded codedError
	if !errors.As(err, &coded) || coded.code != "verification_failed" {
		t.Fatalf("cmdVerify() error = %v, want verification_failed code", err)
	}
}

func TestRestoreKeyIsIdempotentForSameBackup(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	masterKey := bytes32(0x55)
	firstType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("first restoreKey() error = %v", err)
	}
	secondType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("second restoreKey() error = %v", err)
	}
	if firstType != "ed25519" || secondType != "ed25519" {
		t.Fatalf("restoreKey() key types = %q, %q, want ed25519 both times", firstType, secondType)
	}
	if _, err := os.Stat(apkeys.AccountKeyFilePath(keystorePaths(), address)); err != nil {
		t.Fatalf("restored key file missing after repeated restore: %v", err)
	}
}

func TestRestoreKeyDoesNotActivateLibraryVisibleCompiledProvider(t *testing.T) {
	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	masterKey := bytes32(0x8a)
	keyType := "restore-library-provider-v1"
	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)

	registerRestoreLibraryProvider(keyType)

	keyJSON := canonicalDSALSigKeyJSONForApstore(t, keyType, keyType, bytecode)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	if keyTypeEnabled(keystorePaths(), productIdentityID(), keyType) {
		t.Fatal("test setup unexpectedly has activation record")
	}

	restoredKeyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("restoreKey() error = %v", err)
	}
	if restoredKeyType != keyType {
		t.Fatalf("restoreKey() keyType = %q, want %q", restoredKeyType, keyType)
	}
	if keyTypeEnabled(keystorePaths(), productIdentityID(), keyType) {
		t.Fatal("credential restore changed destination key-type state")
	}
}

func TestRestoreKeyAllowsInstalledTemplateWithoutBundle(t *testing.T) {
	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	paths := keystorePaths()
	identityID := productIdentityID()
	masterKey := bytes32(0x8b)
	keyType := "aplane.htlc.v1"
	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)

	templateYAML, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.htlc.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.htlc.v1.yaml) error = %v", err)
	}
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), templateYAML, keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SaveTemplateActive() error = %v", err)
	}
	writeTemplateStateForApstoreTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	keyJSON := canonicalGenericKeyJSONForApstore(t, keyType, bytecode)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	restoredKeyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("restoreKey() error = %v", err)
	}
	if restoredKeyType != keyType {
		t.Fatalf("restoreKey() keyType = %q, want %q", restoredKeyType, keyType)
	}
	if _, err := os.Stat(apkeys.AccountKeyFilePath(keystorePaths(), address)); err != nil {
		t.Fatalf("restored key file missing: %v", err)
	}
}

func TestRestoreKeyRejectsLogicSigWithoutSigningMetadata(t *testing.T) {
	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	masterKey := bytes32(0x8c)
	keyType := "missing-restore-template-v1"
	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)

	keyJSON := canonicalGenericKeyWithoutSigningMetadataForApstore(t, keyType, bytecode)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	restoredKeyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err == nil {
		t.Fatal("restoreKey() error = nil, want missing signing metadata rejection")
	}
	if restoredKeyType != "" {
		t.Fatalf("restoreKey() keyType = %q, want empty on failure", restoredKeyType)
	}
	if !strings.Contains(err.Error(), "signing_metadata_version") {
		t.Fatalf("restoreKey() error = %v, want signing metadata context", err)
	}
	if _, statErr := os.Stat(apkeys.AccountKeyFilePath(keystorePaths(), address)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no key file written after missing signing metadata, got stat err=%v", statErr)
	}
}

func TestRestoreKeyDoesNotInstallShippedLibraryGenericTemplateWithoutBundle(t *testing.T) {
	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	masterKey := bytes32(0x8d)
	keyType := "aplane.htlc.v1"
	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)

	templateYAML, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.htlc.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.htlc.v1.yaml) error = %v", err)
	}
	if err := os.MkdirAll(keystorePaths().TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("MkdirAll(TemplateLibraryDir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keystorePaths().TemplateLibraryDir(), "aplane.htlc.v1.yaml"), templateYAML, 0o644); err != nil {
		t.Fatalf("WriteFile(aplane.htlc.v1.yaml) error = %v", err)
	}

	keyJSON := canonicalGenericKeyJSONForApstore(t, keyType, bytecode)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	restoredKeyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("restoreKey() error = %v", err)
	}
	if restoredKeyType != keyType {
		t.Fatalf("restoreKey() keyType = %q, want %q", restoredKeyType, keyType)
	}
	if templatestore.TemplateExistsForPaths(keystorePaths(), productIdentityID(), keyType, templatestore.TemplateTypeGeneric) {
		t.Fatal("expected standalone key restore not to materialize shipped library generic template")
	}
}

func TestRestoreKeyDoesNotInstallShippedLibraryComposedTemplateWithoutBundle(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	masterKey := bytes32(0x8e)
	keyType := "aplane.falcon1024-timelock.v1"
	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)

	templateYAML, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.falcon1024-timelock.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.falcon1024-timelock.v1.yaml) error = %v", err)
	}
	if err := os.MkdirAll(keystorePaths().TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("MkdirAll(TemplateLibraryDir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keystorePaths().TemplateLibraryDir(), "aplane.falcon1024-timelock.v1.yaml"), templateYAML, 0o644); err != nil {
		t.Fatalf("WriteFile(aplane.falcon1024-timelock.v1.yaml) error = %v", err)
	}

	keyJSON := canonicalDSALSigKeyJSONForApstore(t, keyType, "aplane.falcon1024.v1", bytecode)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	restoredKeyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("restoreKey() error = %v", err)
	}
	if restoredKeyType != keyType {
		t.Fatalf("restoreKey() keyType = %q, want %q", restoredKeyType, keyType)
	}
	if templatestore.TemplateExistsForPaths(keystorePaths(), productIdentityID(), keyType, templatestore.TemplateTypeComposed) {
		t.Fatal("expected standalone key restore not to materialize shipped library composed template")
	}
}

func TestRestoreKeyDoesNotEnableDisabledInstalledTemplateWithoutBundle(t *testing.T) {
	dataDirectory = t.TempDir()
	genstoretest.MintFirst(t, keystorePaths())
	backupDir := t.TempDir()
	paths := keystorePaths()
	identityID := productIdentityID()
	masterKey := bytes32(0x8f)
	keyType := "aplane.htlc.v1"
	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)

	templateYAML, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.htlc.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.htlc.v1.yaml) error = %v", err)
	}
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), templateYAML, keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SaveTemplateActive() error = %v", err)
	}
	writeTemplateStateForApstoreTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateDisabled)

	keyJSON := canonicalGenericKeyJSONForApstore(t, keyType, bytecode)
	if err := writeStandaloneBackup(backupDir, address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}

	if _, err := restoreKey(backupDir, address, cryptotest.Keyring(t, masterKey), []byte("export-passphrase")); err != nil {
		t.Fatalf("restoreKey() error = %v", err)
	}
	if !keyTypeDisabled(paths, identityID, keyType) {
		t.Fatal("expected standalone key restore to leave disabled installed template disabled")
	}
}

func keyTypeEnabled(paths storepaths.Paths, identityID, keyType string) bool {
	rec, ok, err := keytypestate.Get(paths, keyType)
	return err == nil && ok && rec.State == keytypestate.StateEnabled
}

func keyTypeDisabled(paths storepaths.Paths, identityID, keyType string) bool {
	rec, ok, err := keytypestate.Get(paths, keyType)
	return err == nil && ok && rec.State == keytypestate.StateDisabled
}

func writeTemplateStateForApstoreTest(t *testing.T, paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType, state keytypestate.State) {
	t.Helper()
	var source keytypestate.Source
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		source = keytypestate.SourceYAMLGeneric
	case templatestore.TemplateTypeComposed:
		source = keytypestate.SourceYAMLComposed
	default:
		t.Fatalf("unsupported template type in test: %q", templateType)
	}
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  source,
		State:   state,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

func TestRestoreKeyMetadataUsesGenericLogicSigBytecode(t *testing.T) {
	bytecode := saltedLogicSigBytecodeForTest()
	keyJSON := canonicalGenericKeyJSONForApstore(t, "test.generic-policy.v1", bytecode)

	keyType, address, hasLogicSigBytecode, err := restoreKeyMetadata(keyJSON)
	if err != nil {
		t.Fatalf("restoreKeyMetadata() error = %v", err)
	}
	if keyType != "test.generic-policy.v1" {
		t.Fatalf("restoreKeyMetadata() keyType = %q, want test.generic-policy.v1", keyType)
	}
	if address != logicSigAddressForTestForBytes(t, bytecode) {
		t.Fatalf("restoreKeyMetadata() address = %q, want %q", address, logicSigAddressForTestForBytes(t, bytecode))
	}
	if !hasLogicSigBytecode {
		t.Fatal("restoreKeyMetadata() hasLogicSigBytecode = false, want true")
	}
}

func testSentryComponentKeyJSONForApstore(t *testing.T) (string, []byte) {
	t.Helper()
	return keystest.SentryComponentFalcon1024KeyJSON(t, 0xcd)
}
