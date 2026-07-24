// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRemoveBatchRemovesPublishedInventory(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x7b}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)

	if err := RemoveBatch(paths, "default", batch.RestoreID); err != nil {
		t.Fatalf("RemoveBatch() error = %v", err)
	}
	if _, err := os.Lstat(paths.RecoveredBatchDir("default", batch.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("removed batch stat error = %v, want not found", err)
	}
	listed, err := List(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("List() = %+v, want empty", listed)
	}
}

func TestRemoveBatchRejectsInvalidRestoreID(t *testing.T) {
	err := RemoveBatch(storepaths.NewPaths(t.TempDir()), "default", "../batch")
	if err == nil {
		t.Fatal("RemoveBatch() error = nil, want invalid restore ID")
	}
}
