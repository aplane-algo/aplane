// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdBackupImportRejectsInvalidSources(t *testing.T) {
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	if err := cmdBackupImport(filepath.Join(t.TempDir(), "backup.zip")); err == nil {
		t.Fatal("cmdBackupImport(non-archive) error = nil, want extension rejection")
	} else if !strings.Contains(err.Error(), "must end in .tar.gz or .tgz") {
		t.Fatalf("cmdBackupImport(non-archive) error = %v, want extension context", err)
	}

	if err := cmdBackupImport(filepath.Join(t.TempDir(), "missing.tar.gz")); err == nil {
		t.Fatal("cmdBackupImport(missing) error = nil, want missing source rejection")
	} else if !strings.Contains(err.Error(), "backup source unavailable") {
		t.Fatalf("cmdBackupImport(missing) error = %v, want missing source context", err)
	}
}

func TestCmdBackupImportRejectsDuplicateBasename(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "restore-source.tar.gz")
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport(archivePath)
	}); err != nil {
		t.Fatalf("first cmdBackupImport() error = %v", err)
	}
	err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport(archivePath)
	})
	if err == nil {
		t.Fatal("second cmdBackupImport() error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second cmdBackupImport() error = %v, want duplicate context", err)
	}
}

func TestBackupImportTemplateValidationClientUsesConfiguredTEALCompileToken(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	var sawCompile bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/teal/compile" {
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
		sawCompile = true
		if got := r.Header.Get("X-Algo-API-Token"); got != "localnet-token" {
			t.Fatalf("X-Algo-API-Token = %q, want localnet-token", got)
		}
		_, _ = w.Write([]byte(`{"result":"AQ==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	}))
	defer server.Close()

	config = serverconfig.ServerConfig{
		TEALCompileNetwork: "localnet",
		Algod: apconfig.AlgodConfig{
			"localnet": &apconfig.AlgodNetworkConfig{
				Server: server.URL,
				Token:  "localnet-token",
			},
		},
	}

	client, err := newBackupImportTemplateValidationClient()
	if err != nil {
		t.Fatalf("newBackupImportTemplateValidationClient() error = %v", err)
	}
	if _, err := client.TealCompile([]byte("#pragma version 8\nint 1\n")).Do(context.Background()); err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	if !sawCompile {
		t.Fatal("mock algod did not receive compile request")
	}
}

func TestRestoreKeyRejectsWrongExportPassphrase(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	backupDir := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)

	encrypted, err := apcrypto.EncryptStandalone(keyJSON, []byte("correct-export-passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, address+".apb"), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	keyType, err := restoreKey(backupDir, address, bytes32(0x11), []byte("wrong-export-passphrase"))
	if err == nil {
		t.Fatal("restoreKey() error = nil, want wrong passphrase failure")
	}
	if keyType != "" {
		t.Fatalf("restoreKey() keyType = %q, want empty on failure", keyType)
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("restoreKey() error = %v, want wrong passphrase context", err)
	}
}

func TestCmdBackupImportUsesManagedBackupDir(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "restore-source.tar.gz")
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport(archivePath)
	}); err != nil {
		t.Fatalf("cmdBackupImport() error = %v", err)
	}
	importedPath := filepath.Join(keystorePaths().IdentityBackupsDir(productIdentityID()), filepath.Base(archivePath))
	if _, err := os.Stat(importedPath); err != nil {
		t.Fatalf("imported archive stat error = %v", err)
	}
	items, err := backup.ListManagedBackups(keystorePaths(), productIdentityID())
	if err != nil {
		t.Fatalf("ListManagedBackups() error = %v", err)
	}
	if len(items) != 1 || items[0].FileName != filepath.Base(archivePath) {
		t.Fatalf("managed backups = %+v, want %s", items, filepath.Base(archivePath))
	}
	if len(items) != 1 || !items[0].Verified {
		t.Fatalf("managed backup import = %+v, want verified listed item", items)
	}
}

func TestCmdRestoreApplyManagedPreviewsBeforeApply(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		previewResult: protocol.RestorePreviewMessage{
			Keys: []protocol.RestoreKeyInfo{{Address: "ADDR", KeyType: "ed25519"}},
		},
		restoreResult: protocol.RestoreBackupResultMessage{
			Success:  true,
			Restored: []protocol.RestoreKeyInfo{{Address: "ADDR", KeyType: "ed25519"}},
			KeyCount: 1,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\ny\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz", "--address", "ADDR", "--overwrite"})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged() error = %v", err)
	}

	wantRequests := []string{protocol.MsgTypePreviewRestore, protocol.MsgTypeRestoreBackup}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
	if fake.restoreRequest.ArchivePath != "restore-source.tar.gz" {
		t.Fatalf("restore archive = %q, want restore-source.tar.gz", fake.restoreRequest.ArchivePath)
	}
	if len(fake.restoreRequest.Addresses) != 1 || fake.restoreRequest.Addresses[0] != "ADDR" {
		t.Fatalf("restore addresses = %v, want [ADDR]", fake.restoreRequest.Addresses)
	}
	if !fake.restoreRequest.Overwrite {
		t.Fatal("restore overwrite = false, want true")
	}
}

func TestCmdRestoreApplyManagedStopsWhenPreviewFails(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		previewResult: protocol.RestorePreviewMessage{
			Code:  protocol.ResultCodeRestorePreviewFailed,
			Error: "bad backup",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz"})
	})
	if err == nil {
		t.Fatal("cmdRestoreApplyManaged() error = nil, want preview failure")
	}
	if !strings.Contains(err.Error(), "bad backup") {
		t.Fatalf("cmdRestoreApplyManaged() error = %v, want bad backup", err)
	}
	wantRequests := []string{protocol.MsgTypePreviewRestore}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
}

func TestCmdRestoreApplyManagedStopsWhenBackupArchiveMissing(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		previewResult: protocol.RestorePreviewMessage{
			Code:  "backup_not_found",
			Error: "backup archive not found",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"missing.tar.gz"})
	})
	if err == nil {
		t.Fatal("cmdRestoreApplyManaged() error = nil, want missing backup archive failure")
	}
	if !strings.Contains(err.Error(), "backup archive not found") {
		t.Fatalf("cmdRestoreApplyManaged() error = %v, want missing archive context", err)
	}
	wantRequests := []string{protocol.MsgTypePreviewRestore}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
}
