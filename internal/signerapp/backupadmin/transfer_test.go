// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestBackupTransferImportsAndExportsInBoundedChunks(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})

	sourceDir := t.TempDir()
	payload := make([]byte, 600*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "payload.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "source.tar.gz")
	if err := backup.CreateTarGzArchive(sourceDir, archivePath); err != nil {
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

	begin := service.BeginBackupImport(ir, adminproto.BeginBackupImportRequest{FileName: "imported.tar.gz"})
	if !begin.Success || begin.UploadID == "" {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	var offset int64
	for offset < int64(len(archiveBytes)) {
		end := offset + adminproto.BackupTransferChunkBytes
		if end > int64(len(archiveBytes)) {
			end = int64(len(archiveBytes))
		}
		result := service.AppendBackupImport(ir, adminproto.AppendBackupImportRequest{
			UploadID: begin.UploadID, Offset: offset, Data: archiveBytes[offset:end],
		})
		if !result.Success || result.NextOffset != end {
			t.Fatalf("AppendBackupImport() = %#v", result)
		}
		offset = end
	}
	commit := service.CommitBackupImport(ir, adminproto.CommitBackupImportRequest{
		UploadID: begin.UploadID, FileName: "imported.tar.gz", ExpectedSize: size, ExpectedSHA256: checksum,
	})
	if !commit.Success || commit.Backup.Size != size {
		t.Fatalf("CommitBackupImport() = %#v", commit)
	}

	var exported []byte
	offset = 0
	for {
		chunk := service.ReadBackupChunk(ir, adminproto.ReadBackupChunkRequest{FileName: "imported.tar.gz", Offset: offset})
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

func TestBackupTransferRejectsWrongOffsetAndChecksum(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{paths: paths}}
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})
	begin := service.BeginBackupImport(ir, adminproto.BeginBackupImportRequest{FileName: "bad.tar.gz"})
	if !begin.Success {
		t.Fatalf("BeginBackupImport() = %#v", begin)
	}
	if result := service.AppendBackupImport(ir, adminproto.AppendBackupImportRequest{UploadID: begin.UploadID, Offset: 1, Data: []byte("x")}); result.Success {
		t.Fatalf("AppendBackupImport(wrong offset) = %#v", result)
	}
	if result := service.AppendBackupImport(ir, adminproto.AppendBackupImportRequest{UploadID: begin.UploadID, Data: []byte("x")}); !result.Success {
		t.Fatalf("AppendBackupImport() = %#v", result)
	}
	if result := service.CommitBackupImport(ir, adminproto.CommitBackupImportRequest{UploadID: begin.UploadID, FileName: "bad.tar.gz", ExpectedSize: 1, ExpectedSHA256: string(bytes.Repeat([]byte("0"), 64))}); result.Success {
		t.Fatalf("CommitBackupImport(wrong checksum) = %#v", result)
	}
}
