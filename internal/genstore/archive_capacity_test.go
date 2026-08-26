// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestDeletedArchiveLimitsReserveEmergencyDeletion(t *testing.T) {
	if DeletedArchiveWarnEntries+1 != DeletedArchiveMaxEntries {
		t.Fatalf("entry warning threshold does not reserve exactly one deletion")
	}
	if DeletedArchiveWarnEncodedBytes+cryptoMaxEnvelopeForTest() != DeletedArchiveMaxEncodedBytes {
		t.Fatalf("byte warning threshold does not reserve one maximum envelope")
	}
	if (DeletedArchiveUsage{Entries: DeletedArchiveWarnEntries}).Warning() {
		t.Fatal("warning fired before entry reserve was consumed")
	}
	if !(DeletedArchiveUsage{Entries: DeletedArchiveMaxEntries}).Warning() {
		t.Fatal("warning did not fire when entry reserve was consumed")
	}
}

func TestInspectDeletedArchiveAndAppendPreflight(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	active := mintTestGeneration(t, paths, testGenA, nil)
	credential := filepath.Join(active.KeysDir(), "TEST.key")
	if err := os.WriteFile(credential, []byte("credential-envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	usage, err := PreflightDeletedArchiveAppend(active, credential)
	if err != nil {
		t.Fatalf("PreflightDeletedArchiveAppend() error = %v", err)
	}
	if usage.Entries != 1 || usage.EncodedBytes != int64(len("credential-envelope")) {
		t.Fatalf("prospective usage = %+v", usage)
	}
	actual, err := InspectDeletedArchive(active)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Entries != 0 || actual.EncodedBytes != 0 {
		t.Fatalf("preflight mutated archive: %+v", actual)
	}
}

func TestDeletedArchiveHardLimitErrorNamesPrune(t *testing.T) {
	err := validateDeletedArchiveUsage(DeletedArchiveUsage{Entries: DeletedArchiveMaxEntries + 1})
	if err == nil || !strings.Contains(err.Error(), "authenticated prune") {
		t.Fatalf("limit error = %v", err)
	}
}

func cryptoMaxEnvelopeForTest() int64 {
	return int64(DeletedArchiveMaxEncodedBytes - DeletedArchiveWarnEncodedBytes)
}
