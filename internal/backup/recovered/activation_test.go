// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCreateLoadUpdateAndRemoveActivation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x71}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	fileData := []byte("prior encrypted key")
	fileSum := sha256.Sum256(fileData)
	journal := ActivationJournal{
		RestoreID:                   batch.RestoreID,
		CreatedAt:                   time.Unix(1_700_000_000, 0).UTC(),
		State:                       ActivationApplying,
		ReviewToken:                 string64("a"),
		DestinationPolicySHA256:     string64("b"),
		DestinationApprovalMode:     "manual_default",
		AcknowledgePolicyTransition: true,
	}
	snapshot := RollbackSnapshot{
		RestoreID: batch.RestoreID,
		Directories: []RollbackDirectory{
			{
				RelativePath: "keys",
				Existed:      true,
				Files: []RollbackFile{
					{
						Name:   "prior.key",
						Mode:   0o600,
						SHA256: hex.EncodeToString(fileSum[:]),
						Data:   fileData,
					},
				},
			},
			{RelativePath: "keytypes", Existed: false},
		},
	}

	if err := CreateActivation(paths, "default", journal, snapshot, masterKey); err != nil {
		t.Fatalf("CreateActivation() error = %v", err)
	}
	loadedJournal, loadedSnapshot, err := LoadActivation(paths, "default", batch.RestoreID, masterKey)
	if err != nil {
		t.Fatalf("LoadActivation() error = %v", err)
	}
	if loadedJournal.State != ActivationApplying || loadedJournal.ReviewToken != journal.ReviewToken {
		t.Fatalf("loaded journal = %+v", loadedJournal)
	}
	if len(loadedSnapshot.Directories) != 2 ||
		string(loadedSnapshot.Directories[0].Files[0].Data) != string(fileData) {
		t.Fatalf("loaded snapshot = %+v", loadedSnapshot)
	}
	loadedSnapshot.Zero()

	if err := UpdateActivationState(paths, "default", batch.RestoreID, ActivationRollingBack, masterKey); err != nil {
		t.Fatalf("UpdateActivationState() error = %v", err)
	}
	loadedJournal, loadedSnapshot, err = LoadActivation(paths, "default", batch.RestoreID, masterKey)
	if err != nil {
		t.Fatalf("LoadActivation(updated) error = %v", err)
	}
	loadedSnapshot.Zero()
	if loadedJournal.State != ActivationRollingBack {
		t.Fatalf("updated state = %q, want rolling_back", loadedJournal.State)
	}

	if err := RemoveActivation(paths, "default", batch.RestoreID); err != nil {
		t.Fatalf("RemoveActivation() error = %v", err)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir("default", batch.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("activation dir stat error = %v, want not found", err)
	}
	if _, err := LoadBatch(paths, "default", batch.RestoreID, masterKey); err != nil {
		t.Fatalf("batch was removed with activation state: %v", err)
	}
}

func string64(value string) string {
	return value + string(bytes.Repeat([]byte(value), 63))
}
