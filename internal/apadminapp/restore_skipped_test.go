// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func previewStoreForTest(preview protocol.RestorePreviewMessage) (Store, *bytes.Buffer, *bytes.Buffer) {
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.PreviewRestoreMessage); !ok {
			return errors.New("unexpected request")
		}
		*result.(*protocol.RestorePreviewMessage) = preview
		return nil
	}}
	var stdout, stderr bytes.Buffer
	return Store{
		Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr},
		ReadSecret: func(string) ([]byte, error) { return []byte("export-secret"), nil },
	}, &stdout, &stderr
}

// A batch preview lists the keys a restore would admit and the ones it would
// skip, with the reason, and succeeds while anything is left to restore.
func TestStoreRestorePreviewListsSkippedKeys(t *testing.T) {
	store, stdout, stderr := previewStoreForTest(protocol.RestorePreviewMessage{
		ArchivePath:    "backup.tar.gz",
		Keys:           []protocol.RestoreKeyInfo{{Address: "GOODADDR", KeyType: "ed25519"}},
		Skipped:        []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
		SkippedOmitted: 3,
	})
	if err := store.RunRestore([]string{"preview", "backup.tar.gz"}); err != nil {
		t.Fatalf("RunRestore(preview) error = %v", err)
	}
	for _, want := range []string{"GOODADDR  ed25519  new", "BADADDR  skipped: failed to parse backup credential", "and 3 more skipped key(s) not listed"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("%q missing from stdout %q", want, stdout.String())
		}
	}
	if !strings.Contains(stderr.String(), "4 key(s) cannot be restored on this node and would be skipped") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// A batch preview with nothing left to restore lists every skipped key and
// fails.
func TestStoreRestorePreviewWithNothingToRestoreFails(t *testing.T) {
	store, stdout, _ := previewStoreForTest(protocol.RestorePreviewMessage{
		ArchivePath: "backup.tar.gz",
		Skipped:     []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
	})
	err := store.RunRestore([]string{"preview", "backup.tar.gz"})
	if err == nil || err.Error() != "nothing to restore: every key in the backup would be skipped" {
		t.Fatalf("RunRestore(preview) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "BADADDR  skipped: failed to parse backup credential") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

// A batch restore reports each key it skipped and counts them.
func TestStoreRestoreApplyReportsSkippedKeys(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		*result.(*protocol.RestoreBackupResultMessage) = protocol.RestoreBackupResultMessage{
			Success: true, GenerationID: "gen-2",
			Restored: []protocol.RestoreCredential{{Selector: "GOODADDR"}}, RestoredOmitted: 2, IdenticalOmitted: 3,
			Skipped: []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
		}
		return nil
	}}
	var stderr bytes.Buffer
	store := Store{
		Client: requester, Streams: Streams{Stderr: &stderr},
		ReadSecret: func(string) ([]byte, error) { return []byte("export-secret"), nil },
	}
	if err := store.RunRestore([]string{"apply", "backup.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"skipped BADADDR: failed to parse backup credential", "restored 3 credential(s); 3 already identical; 1 skipped"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("%q missing from stderr %q", want, stderr.String())
		}
	}
}

// A batch import of an archive holding keys a restore would skip succeeds
// and names each one with the reason.
func TestStoreBackupImportReportsSkippedKeys(t *testing.T) {
	root := t.TempDir()
	if err := backup.WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1, 0), []byte("export-secret"), nil); err != nil {
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
			*result.(*protocol.CommitBackupImportResultMessage) = protocol.CommitBackupImportResultMessage{
				Success: true, Skipped: []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
			}
		default:
			return errors.New("unexpected request")
		}
		return nil
	}}
	var stderr bytes.Buffer
	store := Store{
		Client: requester, Streams: Streams{Stderr: &stderr},
		ReadSecret: func(string) ([]byte, error) { return []byte("export-secret"), nil },
	}
	if err := store.RunBackup([]string{"import", archive}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"backup imported: backup.tar.gz", "A restore will skip 1 key(s) in it that this node cannot use:",
		"  BADADDR: failed to parse backup credential",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("%q missing from stderr %q", want, stderr.String())
		}
	}
}

// The heading before an import's skipped keys says what a restore on this
// node does with them: skips them, or, for an archive of another role,
// refuses it whole.
func TestImportSkipHeading(t *testing.T) {
	skipped := []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "refused"}}
	for _, tc := range []struct {
		result protocol.CommitBackupImportResultMessage
		want   string
	}{
		{protocol.CommitBackupImportResultMessage{}, ""},
		{protocol.CommitBackupImportResultMessage{Skipped: skipped, SkippedOmitted: 2}, "A restore will skip 3 key(s) in it that this node cannot use:"},
		{protocol.CommitBackupImportResultMessage{SourceNodeRole: "cosigner"}, "Backed up from a cosigner node, so a restore on this node refuses it."},
		{protocol.CommitBackupImportResultMessage{SourceNodeRole: "cosigner", Skipped: skipped}, "Backed up from a cosigner node, so a restore on this node refuses it. 1 key(s) in it cannot be used on this node:"},
	} {
		if got := ImportSkipHeading(tc.result); got != tc.want {
			t.Fatalf("ImportSkipHeading(%+v) = %q, want %q", tc.result, got, tc.want)
		}
	}
}
