// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
)

const saltCounterForTest byte = 5

func saltedLogicSigBytecodeForTest() []byte {
	return []byte{0x26, 0x01, 0x01, saltCounterForTest, 0x81, 0x01}
}

func TestDeepVerifyBackupValidStandaloneCredential(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	root, keysDir := newVerifyArchive(t)
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	sealTestArchiveManifest(t, root)
	report, err := DeepVerifyBackup(root, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestDeepVerifyBackupRejectsPlaintextPayload(t *testing.T) {
	root, keysDir := newVerifyArchive(t)
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := os.WriteFile(filepath.Join(keysDir, address+".apb"), keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	sealTestArchiveManifest(t, root)
	report, err := DeepVerifyBackup(root, "export-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if report.FailedFiles != 1 || !strings.Contains(report.Results[0].Error, "must be encrypted") {
		t.Fatalf("report = %+v", report)
	}
}

func TestDeepVerifyBackupRejectsInternalBundle(t *testing.T) {
	root, keysDir := newVerifyArchive(t)
	address, _ := testEd25519BackupKeyJSON(t)
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), []byte(`{"backup_bundle":1,"key":{}}`), []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	sealTestArchiveManifest(t, root)
	report, err := DeepVerifyBackup(root, "export-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if report.FailedFiles != 1 || !strings.Contains(report.Results[0].Error, "unsupported internal backup bundle") {
		t.Fatalf("report = %+v", report)
	}
}

func TestDeepVerifyBackupRejectsAddressMismatch(t *testing.T) {
	root, keysDir := newVerifyArchive(t)
	_, keyJSON := testEd25519BackupKeyJSON(t)
	other, _ := testEd25519BackupKeyJSON(t)
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, other+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	sealTestArchiveManifest(t, root)
	report, err := DeepVerifyBackup(root, "export-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if report.FailedFiles != 1 || !strings.Contains(report.Results[0].Error, "address mismatch") {
		t.Fatalf("report = %+v", report)
	}
}

func newVerifyArchive(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}
	return root, keysDir
}

func testEd25519BackupKeyJSON(t *testing.T) (string, []byte) {
	t.Helper()
	return keystest.Ed25519KeyJSON(t)
}

func writeStandaloneBackupFile(path string, plaintext, exportPassphrase []byte) error {
	encrypted, err := apcrypto.EncryptStandalone(plaintext, exportPassphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0o600)
}

func sealTestArchiveManifest(t *testing.T, root string) {
	t.Helper()
	if err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		[]byte("export-passphrase"),
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
}
