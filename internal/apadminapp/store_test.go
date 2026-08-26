// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestStoreAuthModeRejectsMalformedBeforeAuthentication(t *testing.T) {
	for _, command := range [][]string{
		{"backup"},
		{"backup", "create"},
		{"backup", "list", "extra"},
		{"restore", "apply", "archive", "--address"},
		{"restore", "unknown"},
		{"changepass", "extra"},
	} {
		if _, err := StoreAuthMode(command[0], command[1:]); err == nil {
			t.Fatalf("StoreAuthMode(%v) error = nil", command)
		}
	}
}

func TestStoreBackupCreateAndList(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		switch request := message.(type) {
		case protocol.BackupMessage:
			if string(request.ExportPassphrase) != "export-secret" || len(request.Addresses) != 1 || request.Addresses[0] != "ADDR" {
				return errors.New("unexpected backup request")
			}
			*result.(*protocol.BackupResultMessage) = protocol.BackupResultMessage{Success: true, ArchivePath: "backup.tar.gz", ArchiveChecksum: "sum", ArchiveSize: 100, KeyCount: 1, Verified: true}
		case protocol.ListBackupsMessage:
			*result.(*protocol.BackupsListMessage) = protocol.BackupsListMessage{Backups: []protocol.BackupInfo{{FileName: "backup.tar.gz", Size: 100, Checksum: "sum"}}}
		default:
			return errors.New("unexpected request")
		}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	store := Store{
		Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr},
		ReadConfirmed: func(string, string) ([]byte, error) { return []byte("export-secret"), nil },
	}
	if err := store.RunBackup([]string{"create", "address", "ADDR"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RunBackup([]string{"list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "managed backup created") || !strings.Contains(stdout.String(), "backup.tar.gz  100 B  sum") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestStoreBackupExportVerifiesAndRefusesReplacement(t *testing.T) {
	payload := []byte("managed backup bytes")
	checksum := testSHA256(payload)
	requester := &fakeRequester{handle: func(message, result any) error {
		switch request := message.(type) {
		case protocol.ListBackupsMessage:
			*result.(*protocol.BackupsListMessage) = protocol.BackupsListMessage{Backups: []protocol.BackupInfo{{FileName: "backup.tar.gz", Size: int64(len(payload)), Checksum: checksum}}}
		case protocol.ReadBackupChunkMessage:
			if request.Offset != 0 {
				return errors.New("unexpected offset")
			}
			*result.(*protocol.BackupChunkMessage) = protocol.BackupChunkMessage{Success: true, Offset: 0, Data: payload, EOF: true}
		default:
			return errors.New("unexpected request")
		}
		return nil
	}}
	destination := filepath.Join(t.TempDir(), "exports")
	store := Store{Client: requester}
	if err := store.RunBackup([]string{"export", checksum, destination}); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(destination, "backup.tar.gz")
	data, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("output=%q err=%v", data, err)
	}
	if err := store.RunBackup([]string{"export", checksum, destination}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second export error = %v", err)
	}
}

func TestStoreBackupExportRejectsOffsetAndChecksumMismatch(t *testing.T) {
	for _, test := range []struct {
		name     string
		offset   int64
		checksum string
		want     string
	}{
		{name: "offset", offset: 1, checksum: testSHA256([]byte("data")), want: "returned offset"},
		{name: "checksum", offset: 0, checksum: "wrong", want: "checksum mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requester := &fakeRequester{handle: func(message, result any) error {
				switch message.(type) {
				case protocol.ListBackupsMessage:
					*result.(*protocol.BackupsListMessage) = protocol.BackupsListMessage{Backups: []protocol.BackupInfo{{FileName: "backup.tar.gz", Size: 4, Checksum: test.checksum}}}
				case protocol.ReadBackupChunkMessage:
					*result.(*protocol.BackupChunkMessage) = protocol.BackupChunkMessage{Success: true, Offset: test.offset, Data: []byte("data"), EOF: true}
				}
				return nil
			}}
			err := (Store{Client: requester}).RunBackup([]string{"export", "backup.tar.gz", t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPublishBackupExportHardLinkFallbackIsNoReplace(t *testing.T) {
	tmpPath := filepath.Join(t.TempDir(), "staging")
	destination := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(tmpPath, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Exercise the injectable primitive with a hard-link fallback by using an
	// error recognized on this platform.
	unsupportedErr := syscall.ENOSYS
	if _, err := publishBackupExportNoReplaceWith(tmpPath, destination, func(string, string) error { return unsupportedErr }, os.Link, os.Remove); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "new" {
		t.Fatalf("destination=%q err=%v", data, err)
	}
}

func TestStoreBackupDeleteCancellationSendsNoDelete(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.ListBackupsMessage); ok {
			*result.(*protocol.BackupsListMessage) = protocol.BackupsListMessage{Backups: []protocol.BackupInfo{{FileName: "backup.tar.gz"}}}
			return nil
		}
		return errors.New("delete request must not be sent")
	}}
	err := (Store{Client: requester, Confirm: func(string) bool { return false }}).RunBackup([]string{"delete", "backup.tar.gz"})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error = %v", err)
	}
}

func TestStoreBackupImportUploadsCommitsAndAbortsOnFailure(t *testing.T) {
	for _, failCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "abort"}[failCommit], func(t *testing.T) {
			root := t.TempDir()
			if err := backup.WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1, 0), []byte("export-secret")); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "backup.tar.gz")
			if err := backup.CreateTarGzArchive(root, archive); err != nil {
				t.Fatal(err)
			}
			requester := &fakeRequester{handle: func(message, result any) error {
				switch request := message.(type) {
				case protocol.BeginBackupImportMessage:
					*result.(*protocol.BeginBackupImportResultMessage) = protocol.BeginBackupImportResultMessage{Success: true, UploadID: "upload-1"}
				case protocol.AppendBackupImportMessage:
					*result.(*protocol.AppendBackupImportResultMessage) = protocol.AppendBackupImportResultMessage{Success: true, NextOffset: request.Offset + int64(len(request.Data))}
				case protocol.CommitBackupImportMessage:
					if string(request.ExportPassphrase) != "export-secret" {
						return errors.New("wrong export passphrase")
					}
					*result.(*protocol.CommitBackupImportResultMessage) = protocol.CommitBackupImportResultMessage{Success: !failCommit, Code: "commit_failed", Error: "rejected"}
				case protocol.AbortBackupImportMessage:
					*result.(*protocol.AbortBackupImportResultMessage) = protocol.AbortBackupImportResultMessage{Success: true}
				default:
					return errors.New("unexpected request")
				}
				return nil
			}}
			store := Store{Client: requester, ReadSecret: func(string) ([]byte, error) { return []byte("export-secret"), nil }}
			err := store.RunBackup([]string{"import", archive})
			if failCommit && err == nil {
				t.Fatal("import error = nil")
			}
			if !failCommit && err != nil {
				t.Fatal(err)
			}
			commitTimeout := time.Duration(0)
			aborted := false
			for i, request := range requester.requests {
				switch request.(type) {
				case protocol.CommitBackupImportMessage:
					commitTimeout = requester.timeouts[i]
				case protocol.AbortBackupImportMessage:
					aborted = true
				}
			}
			if commitTimeout != BackupCommitTimeout {
				t.Fatalf("commit timeout = %s", commitTimeout)
			}
			if aborted != failCommit {
				t.Fatalf("aborted = %t, want %t", aborted, failCommit)
			}
		})
	}
}

func TestStoreRestoreApplyPreservesSelectionAndConflicts(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		request := message.(protocol.RestoreBackupMessage)
		if request.ArchivePath != "backup.tar.gz" || len(request.Addresses) != 1 || request.Addresses[0] != "ADDR" || !request.ReplaceExisting || string(request.ExportPassphrase) != "export-secret" {
			return errors.New("unexpected restore request")
		}
		*result.(*protocol.RestoreBackupResultMessage) = protocol.RestoreBackupResultMessage{Success: true, GenerationID: "gen-2"}
		return nil
	}}
	var stderr bytes.Buffer
	store := Store{
		Client: requester, Streams: Streams{Stderr: &stderr},
		ReadSecret: func(string) ([]byte, error) { return []byte("export-secret"), nil },
	}
	if err := store.RunRestore([]string{"apply", "backup.tar.gz", "--address", "ADDR", "--replace-existing"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "generation: gen-2") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestStoreRestoreRollbackDefaultsToCancellation(t *testing.T) {
	requester := &fakeRequester{}
	err := (Store{Client: requester}).RunRestore([]string{"rollback"})
	if err == nil || len(requester.requests) != 0 {
		t.Fatalf("error=%v requests=%d", err, len(requester.requests))
	}
}

func TestStoreChangePassphraseCopiesSecretsAndPreservesCommittedWarning(t *testing.T) {
	current := []byte("current")
	next := []byte("next")
	requester := &fakeRequester{handle: func(message, result any) error {
		request := message.(protocol.ChangeStorePassphraseMessage)
		if string(request.CurrentPassphrase) != "current" || string(request.NewPassphrase) != "next" {
			return errors.New("unexpected secrets")
		}
		// Mutating the caller-owned buffers after message construction must not
		// change the transmitted copies.
		current[0] = 'X'
		next[0] = 'Y'
		if string(request.CurrentPassphrase) != "current" || string(request.NewPassphrase) != "next" {
			return errors.New("message aliases caller secrets")
		}
		*result.(*protocol.ChangeStorePassphraseResultMessage) = protocol.ChangeStorePassphraseResultMessage{
			Success: false, Code: "rotation_failed", Error: "helper failed", RootCommitted: true,
		}
		return nil
	}}
	var stderr bytes.Buffer
	err := (Store{Client: requester, Streams: Streams{Stderr: &stderr}}).ChangePassphrase(current, next)
	if err == nil || protocol.CodeForError(err) != "rotation_failed" {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(stderr.String(), "new passphrase and generation are authoritative") || !strings.Contains(stderr.String(), "reconcile") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func testSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
