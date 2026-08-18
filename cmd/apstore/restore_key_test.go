// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
)

func TestRestoreKeyRejectsWrongExportPassphrase(t *testing.T) {
	RegisterProviders()
	dataDirectory = t.TempDir()
	backupDir := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	encrypted, err := apcrypto.EncryptStandalone(keyJSON, []byte("correct-export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, address+".apb"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	keyType, err := restoreKey(backupDir, address, cryptotest.Keyring(t, bytes32(0x11)), []byte("wrong-export-passphrase"))
	if err == nil || keyType != "" || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("key type=%q error=%v", keyType, err)
	}
}
