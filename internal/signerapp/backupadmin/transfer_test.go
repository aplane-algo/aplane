// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestBackupTransferImportsAndExportsInBoundedChunks(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	archivePath := writeLargeValidImportArchive(t)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "imported.tar.gz"})
	if !begin.Success || begin.UploadID == "" {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	var offset int64
	for offset < int64(len(archiveBytes)) {
		end := offset + adminproto.BackupTransferChunkBytes
		if end > int64(len(archiveBytes)) {
			end = int64(len(archiveBytes))
		}
		result := service.AppendBackupImport(adminproto.AppendBackupImportRequest{
			UploadID: begin.UploadID, Offset: offset, Data: archiveBytes[offset:end],
		})
		if !result.Success || result.NextOffset != end {
			t.Fatalf("AppendBackupImport() = %#v", result)
		}
		offset = end
	}
	commit := service.CommitBackupImport(adminproto.CommitBackupImportRequest{
		UploadID: begin.UploadID, FileName: "imported.tar.gz", ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !commit.Success || commit.Backup.Size != size {
		t.Fatalf("CommitBackupImport() = %#v", commit)
	}

	var exported []byte
	offset = 0
	for {
		chunk := service.ReadBackupChunk(adminproto.ReadBackupChunkRequest{FileName: "imported.tar.gz", Offset: offset})
		if !chunk.Success || chunk.Offset != offset || len(chunk.Data) > adminproto.BackupTransferChunkBytes {
			t.Fatalf("ReadBackupChunk() = %#v", chunk)
		}
		exported = append(exported, chunk.Data...)
		offset += int64(len(chunk.Data))
		if chunk.EOF {
			break
		}
	}
	if !bytes.Equal(exported, archiveBytes) {
		t.Fatal("exported archive differs from imported bytes")
	}
}

func TestBackupImportReportsCommittedWarningAfterDirectorySyncFailure(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	archivePath := writeLargeValidImportArchive(t)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "sync-warning.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	appendBackupImportBytes(t, service, begin.UploadID, archiveBytes)

	originalSync := syncBackupImportDirectory
	syncBackupImportDirectory = func(string) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncBackupImportDirectory = originalSync })

	result := service.CommitBackupImport(adminproto.CommitBackupImportRequest{
		UploadID: begin.UploadID, FileName: "sync-warning.tar.gz", ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !result.Success {
		t.Fatalf("CommitBackupImport() = %#v, want committed success", result)
	}
	if !strings.Contains(result.Warning, "directory durability could not be confirmed") {
		t.Fatalf("CommitBackupImport() warning = %q, want durability warning", result.Warning)
	}
	if _, err := os.Lstat(filepath.Join(paths.ProductBackupsDir(), "sync-warning.tar.gz")); err != nil {
		t.Fatalf("published backup missing after warning: %v", err)
	}
}

func TestBackupTransferRejectsWrongOffsetAndChecksum(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "bad.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	if result := service.AppendBackupImport(adminproto.AppendBackupImportRequest{UploadID: begin.UploadID, Offset: 1, Data: []byte("x")}); result.Success {
		t.Fatalf("AppendBackupImport(wrong offset) = %#v", result)
	}
	if result := service.AppendBackupImport(adminproto.AppendBackupImportRequest{UploadID: begin.UploadID, Data: []byte("x")}); !result.Success {
		t.Fatalf("AppendBackupImport() = %#v", result)
	}
	passphrase := []byte("export-passphrase")
	if result := service.CommitBackupImport(adminproto.CommitBackupImportRequest{UploadID: begin.UploadID, FileName: "bad.tar.gz", ExpectedSize: 1, ExpectedSHA256: string(bytes.Repeat([]byte("0"), 64)), ExportPassphrase: passphrase}); result.Success {
		t.Fatalf("CommitBackupImport(wrong checksum) = %#v", result)
	}
	if !bytes.Equal(passphrase, make([]byte, len(passphrase))) {
		t.Fatal("CommitBackupImport() did not zero the export passphrase")
	}
}

func TestBackupTransferRejectsWrongPassphraseBeforePublication(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	archivePath := writeLargeValidImportArchive(t)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "wrong-passphrase.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	appendBackupImportBytes(t, service, begin.UploadID, archiveBytes)
	result := service.CommitBackupImport(adminproto.CommitBackupImportRequest{
		UploadID: begin.UploadID, FileName: "wrong-passphrase.tar.gz", ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: []byte("wrong-passphrase"),
	})
	if result.Success {
		t.Fatalf("CommitBackupImport(wrong passphrase) = %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(paths.ProductBackupsDir(), "wrong-passphrase.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("unauthenticated archive was published: %v", err)
	}
}

func TestBackupImportDeepVerificationDoesNotHoldIdentityMutationLock(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	deps := &lockingBackupTransferDeps{paths: paths}
	service := Service{Deps: deps}
	archivePath := writeLargeValidImportArchive(t)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "concurrent.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	appendBackupImportBytes(t, service, begin.UploadID, archiveBytes)

	originalVerify := deepVerifyImportedBackup
	verifyStarted := make(chan struct{})
	releaseVerify := make(chan struct{})
	deepVerifyImportedBackup = func(root string, passphrase []byte) (*backup.VerifyReport, error) {
		close(verifyStarted)
		<-releaseVerify
		return originalVerify(root, passphrase)
	}
	t.Cleanup(func() { deepVerifyImportedBackup = originalVerify })

	commitDone := make(chan adminproto.CommitBackupImportResult, 1)
	go func() {
		commitDone <- service.CommitBackupImport(adminproto.CommitBackupImportRequest{
			UploadID: begin.UploadID, FileName: "concurrent.tar.gz", ExpectedSize: size, ExpectedSHA256: checksum,
			ExportPassphrase: []byte("export-passphrase"),
		})
	}()
	select {
	case <-verifyStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("deep verification did not start")
	}

	mutationDone := make(chan struct{})
	go func() {
		_ = deps.WithStoreMutation(func() error {
			close(mutationDone)
			return nil
		})
	}()
	select {
	case <-mutationDone:
	case <-time.After(time.Second):
		t.Fatal("deep verification retained the store mutation lock")
	}
	close(releaseVerify)
	if result := <-commitDone; !result.Success {
		t.Fatalf("CommitBackupImport() = %#v", result)
	}
}

func TestBackupTransferRejectsExtractableInvalidContentsBeforePublication(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload.bin"), []byte("not a credential backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "invalid.tar.gz")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	checksum, size, err := backup.FileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "invalid.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	if appended := service.AppendBackupImport(adminproto.AppendBackupImportRequest{UploadID: begin.UploadID, Data: archiveBytes}); !appended.Success {
		t.Fatalf("AppendBackupImport() = %#v", appended)
	}
	result := service.CommitBackupImport(adminproto.CommitBackupImportRequest{
		UploadID: begin.UploadID, FileName: "invalid.tar.gz", ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if result.Success {
		t.Fatalf("CommitBackupImport(invalid contents) = %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(paths.ProductBackupsDir(), "invalid.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("invalid archive was published: %v", err)
	}
}

func writeLargeValidImportArchive(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	apbDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(apbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	selector, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	encrypted, err := crypto.EncryptStandalone(payload, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apbDir, selector+".apb"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	padding := make([]byte, 600*1024)
	if _, err := rand.Read(padding); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), padding, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "source.tar.gz")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func appendBackupImportBytes(t *testing.T, service Service, uploadID string, data []byte) {
	t.Helper()
	var offset int64
	for offset < int64(len(data)) {
		end := offset + adminproto.BackupTransferChunkBytes
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		result := service.AppendBackupImport(adminproto.AppendBackupImportRequest{
			UploadID: uploadID, Offset: offset, Data: data[offset:end],
		})
		if !result.Success || result.NextOffset != end {
			t.Fatalf("AppendBackupImport() = %#v", result)
		}
		offset = end
	}
}

func TestBackupTransferCapsIncompleteUploadSize(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	begin := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "large.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	path := filepath.Join(paths.ProductBackupsDir(), begin.UploadID)
	if err := os.Truncate(path, adminproto.MaxBackupImportBytes); err != nil {
		t.Fatal(err)
	}
	result := service.AppendBackupImport(adminproto.AppendBackupImportRequest{
		UploadID: begin.UploadID, Offset: adminproto.MaxBackupImportBytes, Data: []byte("x"),
	})
	if result.Success {
		t.Fatalf("AppendBackupImport(over limit) = %#v", result)
	}
}

func TestBeginBackupImportRemovesAbandonedUpload(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	first := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "first.tar.gz"})
	if !first.Success {
		t.Fatalf("first BeginBackupImport() = %#v", first)
	}
	firstPath := filepath.Join(paths.ProductBackupsDir(), first.UploadID)
	second := service.BeginBackupImport(adminproto.BeginBackupImportRequest{FileName: "second.tar.gz"})
	if !second.Success {
		t.Fatalf("second BeginBackupImport() = %#v", second)
	}
	if _, err := os.Lstat(firstPath); !os.IsNotExist(err) {
		t.Fatalf("abandoned upload still exists: %v", err)
	}
}

func TestCleanupIncompleteBackupImportsRemovesValidationResidue(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	dir := paths.ProductBackupsDir()
	residue := filepath.Join(dir, backupValidationPrefix+"crash")
	if err := os.MkdirAll(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(residue, "payload"), []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	claim := filepath.Join(dir, backupClaimPrefix+"crash.part")
	if err := os.WriteFile(claim, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := CleanupIncompleteBackupImports(paths)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if _, err := os.Lstat(residue); !os.IsNotExist(err) {
		t.Fatalf("validation residue still exists: %v", err)
	}
	if _, err := os.Lstat(claim); !os.IsNotExist(err) {
		t.Fatalf("claimed upload residue still exists: %v", err)
	}
}

type lockingBackupTransferDeps struct {
	paths storepaths.Paths
	mu    sync.Mutex
}

func (d *lockingBackupTransferDeps) KeyPaths() storepaths.Paths { return d.paths }
func (d *lockingBackupTransferDeps) DataDir() string            { return d.paths.Root() }
func (d *lockingBackupTransferDeps) Config() *serverconfig.ServerConfig {
	return &serverconfig.ServerConfig{}
}
func (d *lockingBackupTransferDeps) GenesisHashMappings() map[string]string { return nil }
func (d *lockingBackupTransferDeps) RestoreLimiter() RestoreLimiter         { return nil }
func (d *lockingBackupTransferDeps) WithStoreMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fn()
}
func (d *lockingBackupTransferDeps) Logf(string, ...interface{}) {}

func TestCleanupIncompleteBackupImportsRejectsValidationSymlink(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	dir := paths.ProductBackupsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	marker := filepath.Join(target, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(dir, backupValidationPrefix+"link")
	if err := os.Symlink(target, residue); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := CleanupIncompleteBackupImports(paths); err == nil {
		t.Fatal("CleanupIncompleteBackupImports() accepted validation symlink")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("validation symlink target was changed: %v", err)
	}
}

func TestBackupTransferErrorTextRedactsStoreRoot(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "var", "lib", "apsigner")
	err := fmt.Errorf("open %s: permission denied", filepath.Join(root, "backups", "default", "archive.tar.gz"))
	got := backupTransferErrorText(err, root)
	if strings.Contains(got, root) {
		t.Fatalf("backupTransferErrorText() leaked store root: %q", got)
	}
	if !strings.Contains(got, "<signer-store>/backups/default/archive.tar.gz") {
		t.Fatalf("backupTransferErrorText() = %q, want redacted relative context", got)
	}
}
