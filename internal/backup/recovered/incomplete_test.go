// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"bytes"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestIncompleteActivationIDsFindsOnlyPublishedMarkers(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{0x6c}, 32)
	batch := createRotationTestBatch(t, paths, masterKey)
	if got, err := IncompleteActivationIDs(paths, "default"); err != nil || len(got) != 0 {
		t.Fatalf("IncompleteActivationIDs(before) = %v, %v", got, err)
	}
	if err := CreateActivation(paths, "default", ActivationJournal{
		RestoreID:                   batch.RestoreID,
		CreatedAt:                   time.Unix(1_700_000_000, 0).UTC(),
		State:                       ActivationApplying,
		ReviewToken:                 string64("a"),
		DestinationPolicySHA256:     string64("b"),
		DestinationApprovalMode:     "manual_default",
		AcknowledgePolicyTransition: true,
	}, RollbackSnapshot{
		RestoreID: batch.RestoreID,
		Directories: []RollbackDirectory{
			{RelativePath: "keys"},
			{RelativePath: "keytypes"},
		},
	}, masterKey); err != nil {
		t.Fatalf("CreateActivation() error = %v", err)
	}
	got, err := IncompleteActivationIDs(paths, "default")
	if err != nil {
		t.Fatalf("IncompleteActivationIDs() error = %v", err)
	}
	if len(got) != 1 || got[0] != batch.RestoreID {
		t.Fatalf("IncompleteActivationIDs() = %v, want %s", got, batch.RestoreID)
	}
}
