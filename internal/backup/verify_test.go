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

func logicSigBytecodeForTest() []byte {
	return []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
}

func TestDeepVerifyBackupValidStandaloneCredential(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	root, keysDir := newVerifyArchive(t)
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	sealTestArchiveManifest(t, root)
	report, err := DeepVerifyBackupBytes(root, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("DeepVerifyBackupBytes() error = %v", err)
	}
	if len(report.Verified) != 1 || report.Verified[0].Address != address || len(report.Skipped) != 0 || report.Incomplete() != nil {
		t.Fatalf("report = %+v", report)
	}
}

func TestLoadCredentialEntryRejectsOversizedEnvelopeBeforeReadingIt(t *testing.T) {
	keysDir := t.TempDir()
	path := filepath.Join(keysDir, "ADDR.apb")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(apcrypto.MaxStandaloneEnvelopeBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, skip, err := openedArchive{keysDir: keysDir}.loadCredentialEntry("ADDR", []byte("passphrase"), noderole.RoleSigner)
	if skip != nil || err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("loadCredentialEntry() skip = %+v, error = %v, want bounded-read rejection", skip, err)
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
		nil,
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
}
