// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestListRecoveredBatchesSkipsStagingDirectories(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x5a}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	stagingDir := filepath.Join(paths.RecoveredRootDir("default"), StagingDirPrefix+"abandoned")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		t.Fatalf("Mkdir(staging) error = %v", err)
	}

	got, err := List(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List() count = %d, want 1", len(got))
	}
	if got[0].RestoreID != batch.RestoreID || got[0].EntryCount != len(batch.Entries) {
		t.Fatalf("List() batch = %+v, want restore ID %s with %d entries", got[0], batch.RestoreID, len(batch.Entries))
	}
}

func TestListRecoveredBatchesFailsClosedOnUnknownRootEntry(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.RecoveredRootDir("default"), 0o700); err != nil {
		t.Fatalf("MkdirAll(recovered root) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.RecoveredRootDir("default"), "unknown"), []byte("state"), 0o600); err != nil {
		t.Fatalf("WriteFile(unknown) error = %v", err)
	}

	if _, err := List(paths, "default", bytes.Repeat([]byte{0x6a}, 32)); err == nil {
		t.Fatal("List() error = nil, want unknown root entry rejection")
	} else if !strings.Contains(err.Error(), "unexpected recovered batch directory") {
		t.Fatalf("List() error = %v, want unexpected entry context", err)
	}
}
