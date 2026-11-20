// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"errors"
	"strings"
	"testing"

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
		ArchivePath: "backup.tar.gz",
		Keys:        []protocol.RestoreKeyInfo{{Address: "GOODADDR", KeyType: "ed25519"}},
		Skipped:     []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
	})
	if err := store.RunRestore([]string{"preview", "backup.tar.gz"}); err != nil {
		t.Fatalf("RunRestore(preview) error = %v", err)
	}
	for _, want := range []string{"GOODADDR  ed25519  new", "BADADDR  skipped: failed to parse backup credential"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("%q missing from stdout %q", want, stdout.String())
		}
	}
	if !strings.Contains(stderr.String(), "1 key(s) cannot be restored on this node and would be skipped") {
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
			Restored: []protocol.RestoreCredential{{Selector: "GOODADDR"}},
			Skipped:  []protocol.RestoreSkipped{{Selector: "BADADDR", Reason: "failed to parse backup credential"}},
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
	for _, want := range []string{"skipped BADADDR: failed to parse backup credential", "restored 1 credential(s); 0 already identical; 1 skipped"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("%q missing from stderr %q", want, stderr.String())
		}
	}
}
