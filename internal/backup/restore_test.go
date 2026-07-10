// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestResolveManagedBackupPathScopesToIdentityBackupDir(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	root := paths.IdentityBackupsDir("default")

	got, err := ResolveManagedBackupPath(paths, "default", "backup.tar.gz")
	if err != nil {
		t.Fatalf("ResolveManagedBackupPath(relative) error = %v", err)
	}
	if want := filepath.Join(root, "backup.tar.gz"); got != want {
		t.Fatalf("relative path = %q, want %q", got, want)
	}

	got, err = ResolveManagedBackupPath(paths, "default", filepath.Join(root, "backup.tgz"))
	if err != nil {
		t.Fatalf("ResolveManagedBackupPath(abs) error = %v", err)
	}
	if want := filepath.Join(root, "backup.tgz"); got != want {
		t.Fatalf("absolute path = %q, want %q", got, want)
	}

	if _, err := ResolveManagedBackupPath(paths, "default", "../backup.tar.gz"); err == nil {
		t.Fatal("ResolveManagedBackupPath(escape) error = nil, want rejection")
	}
	if _, err := ResolveManagedBackupPath(paths, "default", filepath.Join("nested", "backup.tar.gz")); err == nil {
		t.Fatal("ResolveManagedBackupPath(nested) error = nil, want rejection")
	}
	if _, err := ResolveManagedBackupPath(paths, "default", "backup.zip"); err == nil {
		t.Fatal("ResolveManagedBackupPath(unsupported extension) error = nil, want rejection")
	}
}

func TestResolveManagedBackupPathRejectsSymlinkedIntermediate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	root := paths.IdentityBackupsDir("default")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("MkdirAll(outside) error = %v", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll(root) error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := ResolveManagedBackupPath(paths, "default", filepath.Join("linked", "backup.tar.gz")); err == nil {
		t.Fatal("ResolveManagedBackupPath(symlinked intermediate) error = nil, want rejection")
	}
}

func TestAuthoritativeTemplateForKeyTypeSkipsNonTemplateKeyType(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("MkdirAll(library) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.TemplateLibraryDir(), "notcanonical.yaml"), []byte("template_type: ["), 0o600); err != nil {
		t.Fatalf("WriteFile(non-template library file) error = %v", err)
	}
	restorer := NewRestorer(paths, "default")

	_, _, ok, err := restorer.authoritativeTemplateForKeyType("notcanonical")
	if err != nil {
		t.Fatalf("authoritativeTemplateForKeyType() error = %v, want nil for non-template key type", err)
	}
	if ok {
		t.Fatal("authoritativeTemplateForKeyType() ok = true, want non-template key type skipped")
	}
}

func TestBuildTemplateRestorePlanRejectsStaleLocalTemplateWhenAuthoritativeMatchesBackup(t *testing.T) {
	const (
		identityID = "default"
		family     = "authoritative-stale"
		keyType    = "test.authoritative-stale.v1"
	)

	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("MkdirAll(library) error = %v", err)
	}
	authoritativeTemplate := genericTemplateYAMLForTest(family)
	if err := os.WriteFile(filepath.Join(paths.TemplateLibraryDir(), keyType+".yaml"), authoritativeTemplate, 0o600); err != nil {
		t.Fatalf("WriteFile(authoritative template) error = %v", err)
	}
	staleTemplate := []byte(`schema_version: 1
derivation_version: 1
template_type: generic
template_mode: generated
publisher: test
family: authoritative-stale
version: 1
display_name: Stale Template
description: Stale identity-local template
teal: |
  #pragma version 8
  int 0
  return
`)
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, staleTemplate, keyType, templatestore.TemplateTypeGeneric, testExportMasterKey); err != nil {
		t.Fatalf("SaveTemplateForPaths(stale) error = %v", err)
	}
	writeTemplateStateForBackupTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	restorer := NewRestorer(paths, identityID)
	_, err := restorer.buildTemplateRestorePlan(authoritativeTemplate, keyType, string(templatestore.TemplateTypeGeneric), testExportMasterKey, false)
	if err == nil {
		t.Fatal("buildTemplateRestorePlan() error = nil, want stale local template conflict")
	}
	if !strings.Contains(err.Error(), "existing keystore template does not match authoritative local definition") {
		t.Fatalf("buildTemplateRestorePlan() error = %v, want stale local template conflict", err)
	}
}

func TestListManagedBackupsSortsArchivesAndIgnoresSymlinks(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	dir := paths.IdentityBackupsDir("default")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	oldPath := filepath.Join(dir, "old.tar.gz")
	newPath := filepath.Join(dir, "new.tgz")
	if err := os.WriteFile(oldPath, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile(old) error = %v", err)
	}
	if err := os.WriteFile(newPath, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile(new) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatalf("WriteFile(notes) error = %v", err)
	}
	if err := os.Symlink(oldPath, filepath.Join(dir, "linked.tar.gz")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	oldTime := time.Unix(1700000000, 0)
	newTime := time.Unix(1710000000, 0)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes(old) error = %v", err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatalf("Chtimes(new) error = %v", err)
	}

	backups, err := ListManagedBackups(paths, "default")
	if err != nil {
		t.Fatalf("ListManagedBackups() error = %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("backup count = %d, want 2", len(backups))
	}
	if backups[0].FileName != "new.tgz" || backups[1].FileName != "old.tar.gz" {
		t.Fatalf("backup order = %v, want newest first", []string{backups[0].FileName, backups[1].FileName})
	}
}

func TestStatManagedBackupArchiveRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.tar.gz")
	if err := os.WriteFile(target, []byte("archive"), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	link := filepath.Join(dir, "linked.tar.gz")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if _, err := StatManagedBackupArchive(link); err == nil {
		t.Fatal("StatManagedBackupArchive(symlink) error = nil, want rejection")
	}
	if _, err := StatManagedBackupArchive(target); err != nil {
		t.Fatalf("StatManagedBackupArchive(target) error = %v", err)
	}
}

func TestPreviewRestoreManagedArchiveReportsKeyMetadataAndExistingConflict(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, keyJSON := testEd25519BackupKeyJSON(t)
	archivePath := writeManagedRestoreArchive(t, paths, identityID, func(keysDir string) {
		if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
			t.Fatalf("writeStandaloneBackupFile() error = %v", err)
		}
	})

	if err := os.MkdirAll(paths.KeysDir(identityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	if err := os.WriteFile(paths.KeyFilePath(identityID, address), []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile(existing key) error = %v", err)
	}

	preview, err := PreviewRestoreWithNodeRole(paths, identityID, filepath.Base(archivePath), []byte("export-passphrase"), noderole.DefaultRole())
	if err != nil {
		t.Fatalf("PreviewRestore() error = %v", err)
	}
	if preview.ArchivePath != archivePath {
		t.Fatalf("ArchivePath = %q, want %q", preview.ArchivePath, archivePath)
	}
	if len(preview.Errors) != 0 {
		t.Fatalf("preview errors = %+v, want none", preview.Errors)
	}
	if len(preview.Keys) != 1 {
		t.Fatalf("preview key count = %d, want 1", len(preview.Keys))
	}
	key := preview.Keys[0]
	if key.Address != address || key.KeyType != "ed25519" || !key.AlreadyExists {
		t.Fatalf("preview key = %+v, want ed25519 existing key %s", key, address)
	}
}

func TestPreviewRestoreWithNodeRoleReportsRoleForbiddenKey(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, keyJSON := testEd25519BackupKeyJSON(t)
	archivePath := writeManagedRestoreArchive(t, paths, identityID, func(keysDir string) {
		if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
			t.Fatalf("writeStandaloneBackupFile() error = %v", err)
		}
	})

	preview, err := PreviewRestoreWithNodeRole(paths, identityID, archivePath, []byte("export-passphrase"), noderole.RoleSentry)
	if err != nil {
		t.Fatalf("PreviewRestoreWithNodeRole() error = %v", err)
	}
	if len(preview.Errors) != 1 {
		t.Fatalf("preview errors = %+v, want one role-forbidden error", preview.Errors)
	}
	if !strings.Contains(preview.Errors[0].Error, "role-forbidden") ||
		!strings.Contains(preview.Errors[0].Error, `node role "sentry"`) {
		t.Fatalf("preview error = %q, want sentry role-forbidden context", preview.Errors[0].Error)
	}
	if len(preview.Keys) != 1 || preview.Keys[0].Error == "" {
		t.Fatalf("preview keys = %+v, want keyed role-forbidden error", preview.Keys)
	}
}

func TestPreviewRestoreWrongPassphraseDoesNotLeakAddress(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, keyJSON := testEd25519BackupKeyJSON(t)
	archivePath := writeManagedRestoreArchive(t, paths, identityID, func(keysDir string) {
		if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("correct-passphrase")); err != nil {
			t.Fatalf("writeStandaloneBackupFile() error = %v", err)
		}
	})

	preview, err := PreviewRestoreWithNodeRole(paths, identityID, archivePath, []byte("wrong-passphrase"), noderole.DefaultRole())
	if err != nil {
		t.Fatalf("PreviewRestore() error = %v", err)
	}
	if len(preview.Keys) != 0 {
		t.Fatalf("preview keys = %+v, want none for wrong passphrase", preview.Keys)
	}
	if len(preview.Errors) != 1 {
		t.Fatalf("preview errors = %+v, want one decrypt error", preview.Errors)
	}
	if preview.Errors[0].Address != "" {
		t.Fatalf("preview error leaked address %q for wrong passphrase", preview.Errors[0].Address)
	}
	if strings.Contains(preview.Errors[0].Error, address) {
		t.Fatalf("preview error %q leaked address %s", preview.Errors[0].Error, address)
	}
}

func TestPreviewRestoreUnsupportedEnvelopeDoesNotLeakAddress(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, _ := testEd25519BackupKeyJSON(t)
	archivePath := writeManagedRestoreArchive(t, paths, identityID, func(keysDir string) {
		if err := os.WriteFile(filepath.Join(keysDir, address+".apb"), []byte(`{"envelope_version":99,"nonce":"","ciphertext":""}`), 0o600); err != nil {
			t.Fatalf("WriteFile(unsupported envelope) error = %v", err)
		}
	})

	preview, err := PreviewRestoreWithNodeRole(paths, identityID, archivePath, []byte("export-passphrase"), noderole.DefaultRole())
	if err != nil {
		t.Fatalf("PreviewRestore() error = %v", err)
	}
	if len(preview.Keys) != 0 {
		t.Fatalf("preview keys = %+v, want none for unsupported envelope", preview.Keys)
	}
	if len(preview.Errors) != 1 {
		t.Fatalf("preview errors = %+v, want one envelope error", preview.Errors)
	}
	if preview.Errors[0].Address != "" {
		t.Fatalf("preview error leaked address %q for unsupported envelope", preview.Errors[0].Address)
	}
	if !strings.Contains(preview.Errors[0].Error, "unsupported envelope_version") {
		t.Fatalf("preview error = %q, want unsupported envelope context", preview.Errors[0].Error)
	}
}

func TestPreviewRestoreRejectsPlaintextBackupPayload(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, keyJSON := testEd25519BackupKeyJSON(t)
	archivePath := writeManagedRestoreArchive(t, paths, identityID, func(keysDir string) {
		if err := os.WriteFile(filepath.Join(keysDir, address+".apb"), keyJSON, 0o600); err != nil {
			t.Fatalf("WriteFile(plaintext backup) error = %v", err)
		}
	})

	preview, err := PreviewRestoreWithNodeRole(paths, identityID, archivePath, []byte("export-passphrase"), noderole.DefaultRole())
	if err != nil {
		t.Fatalf("PreviewRestore() error = %v", err)
	}
	if len(preview.Errors) != 1 {
		t.Fatalf("preview.Errors = %d, want 1", len(preview.Errors))
	}
	if !strings.Contains(preview.Errors[0].Error, "backup file must be encrypted") {
		t.Fatalf("preview error = %q, want encrypted rejection", preview.Errors[0].Error)
	}
}

func TestPreviewRestoreRejectsEmptyManagedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	archivePath := writeManagedRestoreArchive(t, paths, identityID, func(keysDir string) {})

	if _, err := PreviewRestoreWithNodeRole(paths, identityID, archivePath, []byte("export-passphrase"), noderole.DefaultRole()); err == nil {
		t.Fatal("PreviewRestore(empty archive) error = nil, want no .apb rejection")
	} else if !strings.Contains(err.Error(), "no .apb files found") {
		t.Fatalf("PreviewRestore(empty archive) error = %v, want no .apb rejection", err)
	}
}

func TestRestoreKeyWritesStorePermissions(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, keyJSON := testEd25519BackupKeyJSON(t)
	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	restorer := NewRestorer(paths, identityID)
	if _, err := restorer.RestoreKey(keysDir, address, testExportMasterKey, []byte("export-passphrase")); err != nil {
		t.Fatalf("RestoreKey() error = %v", err)
	}

	assertStoreDirMode(t, paths.KeysDir(identityID))
	assertFileMode(t, paths.KeyFilePath(identityID, address), fsutil.StoreFilePerm)
}

func TestRestoreKeyRejectsRoleForbiddenComponentBeforeWrite(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	componentKey, keyJSON := testSentryComponentBackupKeyJSON(t)
	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, componentKey+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	restorer := NewRestorer(paths, identityID).WithNodeRole(noderole.RoleSigner)
	_, err := restorer.RestoreKey(keysDir, componentKey, testExportMasterKey, []byte("export-passphrase"))
	if err == nil {
		t.Fatal("RestoreKey() error = nil, want role-forbidden rejection")
	}
	if !strings.Contains(err.Error(), "role-forbidden") || !strings.Contains(err.Error(), keytypes.SentryComponentEd25519V1) {
		t.Fatalf("RestoreKey() error = %v, want sentry-key role-forbidden rejection", err)
	}
	if _, err := os.Stat(paths.KeyFilePath(identityID, componentKey)); !os.IsNotExist(err) {
		t.Fatalf("restored sentry key stat error = %v, want not exist", err)
	}
}

func TestRestoreKeyWritesComponentPublicMetadataOnSentryNode(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	componentKey, keyJSON := testSentryComponentBackupKeyJSON(t)
	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, componentKey+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}
	payload, err := apkeys.ParsePayload(keyJSON)
	if err != nil {
		t.Fatalf("ParsePayload(sentry key) error = %v", err)
	}
	defer payload.ZeroSecrets()

	restorer := NewRestorer(paths, identityID).WithNodeRole(noderole.RoleSentry)
	keyType, err := restorer.RestoreKey(keysDir, componentKey, testExportMasterKey, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("RestoreKey() error = %v", err)
	}
	if keyType != keytypes.SentryComponentEd25519V1 {
		t.Fatalf("RestoreKey() key type = %q, want %q", keyType, keytypes.SentryComponentEd25519V1)
	}

	env, ok, err := apkeys.ReadComponentPublicMetadata(paths, identityID, componentKey)
	if err != nil {
		t.Fatalf("ReadComponentPublicMetadata() error = %v", err)
	}
	if !ok {
		t.Fatal("ReadComponentPublicMetadata() ok = false, want restored sidecar")
	}
	if env.ComponentKey != componentKey {
		t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, componentKey)
	}
	if env.KeyType != keytypes.SentryComponentEd25519V1 {
		t.Fatalf("KeyType = %q, want %q", env.KeyType, keytypes.SentryComponentEd25519V1)
	}
	wantPublicKeyHex := fmt.Sprintf("%x", payload.PublicKey)
	if env.PublicKeyHex != wantPublicKeyHex {
		t.Fatalf("PublicKeyHex = %q, want %q", env.PublicKeyHex, wantPublicKeyHex)
	}
	assertFileMode(t, apkeys.ComponentPublicMetadataPath(paths, identityID, componentKey), fsutil.StoreFilePerm)
}

func TestRestoreKeyWritesCanonicalPathWhenExistingKeyIsNonCanonical(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	encryptedExisting, err := apcrypto.EncryptWithMasterKey(keyJSON, testExportMasterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey(existing) error = %v", err)
	}
	duplicatePath := filepath.Join(paths.KeysDir(identityID), "duplicate.key")
	if err := os.WriteFile(duplicatePath, encryptedExisting, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(duplicate) error = %v", err)
	}

	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	restorer := NewRestorer(paths, identityID)
	keyType, err := restorer.RestoreKey(keysDir, address, testExportMasterKey, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("RestoreKey() error = %v", err)
	}
	if keyType != "ed25519" {
		t.Fatalf("RestoreKey() key type = %q, want ed25519", keyType)
	}
	if _, statErr := os.Stat(paths.KeyFilePath(identityID, address)); statErr != nil {
		t.Fatalf("canonical key file stat error = %v", statErr)
	}
	if _, statErr := os.Stat(duplicatePath); statErr != nil {
		t.Fatalf("duplicate key file stat error = %v", statErr)
	}
}

func TestRestoreKeyRejectsLogicSigWithoutSigningMetadata(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "test.legacy-generic.v1"
	)

	paths := storepaths.NewPaths(t.TempDir())
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address error = %v", err)
	}

	keyJSON, err := json.Marshal(map[string]any{
		"format_version": apkeys.CurrentKeyFormatVersion,
		"category":       apkeys.CategoryGenericLsig,
		"key_type":       keyType,
		"lsig_bytecode":  hex.EncodeToString(bytecode),
		"salt_counter":   saltCounterForTest,
		"created_at":     time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("json.Marshal(canonical key without signing metadata) error = %v", err)
	}

	templateYAML := []byte("schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: test\nfamily: legacy-generic\nversion: 1\ndisplay_name: Legacy\nteal: |\n  int 1\n")
	bundleJSON, err := json.Marshal(BackupBundle{
		BackupBundle: 1,
		Key:          json.RawMessage(keyJSON),
		TemplateYAML: string(templateYAML),
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if err != nil {
		t.Fatalf("json.Marshal(BackupBundle) error = %v", err)
	}

	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	restorer := NewRestorer(paths, identityID)
	if _, err := restorer.RestoreKey(keysDir, address.String(), testExportMasterKey, []byte("export-passphrase")); err == nil {
		t.Fatal("RestoreKey() error = nil, want signing metadata rejection")
	} else if !strings.Contains(err.Error(), "signing_metadata_version") {
		t.Fatalf("RestoreKey() error = %v, want signing metadata rejection", err)
	}

	if _, err := os.Stat(paths.KeyFilePath(identityID, address.String())); !os.IsNotExist(err) {
		t.Fatalf("restored key stat error = %v, want not exist", err)
	}
	templatePath := templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templatestore.TemplateTypeGeneric)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		t.Fatalf("restored template stat error = %v, want not exist", err)
	}
}

func TestRestoreKeyRejectsInvalidKeyTypeBeforeTemplatePathUse(t *testing.T) {
	const (
		identityID     = "default"
		invalidKeyType = "test.bad type.v1"
	)

	paths := storepaths.NewPaths(t.TempDir())
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address error = %v", err)
	}

	payload := apkeys.NewGenericLSigPayload(invalidKeyType, nil, bytecode, saltCounterForTest, "", []apkeys.StoredSigningArg{{
		Name:     "secret",
		Type:     "bytes",
		Required: true,
	}}, "")
	keyJSON, err := apkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(generic) error = %v", err)
	}

	bundleJSON := backupBundleForTest(t, keyJSON, genericTemplateYAMLForTest("bad type"))
	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	restorer := NewRestorer(paths, identityID)
	if _, err := restorer.RestoreKey(keysDir, address.String(), testExportMasterKey, []byte("export-passphrase")); err == nil {
		t.Fatal("RestoreKey() error = nil, want invalid key_type rejection")
	} else if !strings.Contains(err.Error(), "invalid key_type") || !strings.Contains(err.Error(), invalidKeyType) {
		t.Fatalf("RestoreKey() error = %v, want invalid key_type rejection", err)
	}

	if _, err := os.Stat(paths.KeyFilePath(identityID, address.String())); !os.IsNotExist(err) {
		t.Fatalf("restored key stat error = %v, want not exist", err)
	}
	if entries, err := os.ReadDir(paths.KeyTypeRecordsDir(identityID)); err == nil && len(entries) > 0 {
		t.Fatalf("key type records = %v, want none", entries)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadDir(keytypes) error = %v", err)
	}
}

func TestRestoreKeySkipsConflictingBundledTemplateForStandaloneGenericKey(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "test.standalone-conflict.v1"
	)

	paths := storepaths.NewPaths(t.TempDir())
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address error = %v", err)
	}

	payload := apkeys.NewGenericLSigPayload(keyType, nil, bytecode, saltCounterForTest, "", []apkeys.StoredSigningArg{{
		Name:     "secret",
		Type:     "bytes",
		Required: true,
	}}, "")
	keyJSON, err := apkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(generic) error = %v", err)
	}

	existingTemplate := []byte("schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: test\nfamily: standalone-conflict\nversion: 1\ndisplay_name: Existing\nteal: |\n  int 1\n")
	incomingTemplate := []byte("schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: test\nfamily: standalone-conflict\nversion: 1\ndisplay_name: Incoming\nteal: |\n  int 0\n")
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, existingTemplate, keyType, templatestore.TemplateTypeGeneric, testExportMasterKey); err != nil {
		t.Fatalf("SaveTemplateForPaths() error = %v", err)
	}
	writeTemplateStateForBackupTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	bundleJSON, err := json.Marshal(BackupBundle{
		BackupBundle: 1,
		Key:          json.RawMessage(keyJSON),
		TemplateYAML: string(incomingTemplate),
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if err != nil {
		t.Fatalf("json.Marshal(BackupBundle) error = %v", err)
	}

	keysDir := filepath.Join(t.TempDir(), "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	var logs []string
	var warnings []string
	restorer := NewRestorer(paths, identityID).WithLogger(func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}).WithWarningHandler(func(keyType, warning string) {
		warnings = append(warnings, keyType+": "+warning)
	})
	if _, err := restorer.RestoreKey(keysDir, address.String(), testExportMasterKey, []byte("export-passphrase")); err != nil {
		t.Fatalf("RestoreKey() error = %v", err)
	}

	if _, err := os.Stat(paths.KeyFilePath(identityID, address.String())); err != nil {
		t.Fatalf("expected restored key file: %v", err)
	}
	restoredJSON, err := apkeys.ReadDecryptedKeyJSONWithMasterKey(paths.KeyFilePath(identityID, address.String()), testExportMasterKey)
	if err != nil {
		t.Fatalf("ReadDecryptedKeyJSONWithMasterKey() error = %v", err)
	}
	defer apcrypto.ZeroBytes(restoredJSON)
	var restoredKey struct {
		TemplateFingerprint string `json:"template_fingerprint"`
	}
	if err := json.Unmarshal(restoredJSON, &restoredKey); err != nil {
		t.Fatalf("json.Unmarshal(restored key) error = %v", err)
	}
	wantFingerprint, err := templateCompatibilityFingerprint(templatestore.TemplateTypeGeneric, incomingTemplate)
	if err != nil {
		t.Fatalf("templateCompatibilityFingerprint() error = %v", err)
	}
	if restoredKey.TemplateFingerprint != wantFingerprint {
		t.Fatalf("template_fingerprint = %q, want %q", restoredKey.TemplateFingerprint, wantFingerprint)
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "skipped bundled template") {
		t.Fatalf("restore logs = %v, want skipped bundled template notice", logs)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "backup template conflicts with existing keystore definition") {
		t.Fatalf("restore warnings = %v, want structured skipped template warning", warnings)
	}

	templatePath := templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templatestore.TemplateTypeGeneric)
	gotTemplate, err := templatestore.LoadTemplateFromPath(templatePath, testExportMasterKey)
	if err != nil {
		t.Fatalf("LoadTemplateFromPath() error = %v", err)
	}
	if string(gotTemplate) != string(existingTemplate) {
		t.Fatalf("existing template was overwritten\n got: %s\nwant: %s", gotTemplate, existingTemplate)
	}
}

func writeManagedRestoreArchive(t *testing.T, paths storepaths.Paths, identityID string, populate func(keysDir string)) string {
	t.Helper()

	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	populate(keysDir)

	archivePath := filepath.Join(paths.IdentityBackupsDir(identityID), "managed-restore-test.tar.gz")
	if err := CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}
	return archivePath
}

func testSentryComponentBackupKeyJSON(t *testing.T) (string, []byte) {
	t.Helper()
	return keystest.SentryComponentEd25519KeyJSON(t, 0xcd)
}
