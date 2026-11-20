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

// A batch preview of an archive holding a key the node cannot admit prints
// it with its error and fails.
func TestStoreRestorePreviewOfAnInadmissibleKey(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.PreviewRestoreMessage); !ok {
			return errors.New("unexpected request")
		}
		*result.(*protocol.RestorePreviewMessage) = protocol.RestorePreviewMessage{
			ArchivePath: "backup.tar.gz",
			Keys: []protocol.RestoreKeyInfo{
				{Address: "GOODADDR", KeyType: "ed25519"},
				{Address: "BADADDR", Error: "failed to parse backup credential"},
			},
			Errors: []protocol.RestoreError{{Address: "BADADDR", Error: "failed to parse backup credential"}},
		}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	store := Store{
		Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr},
		ReadSecret: func(string) ([]byte, error) { return []byte("export-secret"), nil },
	}
	err := store.RunRestore([]string{"preview", "backup.tar.gz"})
	if err == nil || err.Error() != "restore preview found 1 error(s)" {
		t.Fatalf("RunRestore(preview) error = %v", err)
	}
	for _, want := range []string{"GOODADDR  ed25519  new", "BADADDR  error: failed to parse backup credential"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("%q missing from stdout %q", want, stdout.String())
		}
	}
	if !strings.Contains(stderr.String(), "BADADDR: failed to parse backup credential") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
