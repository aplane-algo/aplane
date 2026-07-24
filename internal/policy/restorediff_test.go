// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "testing"

func TestDiffForRestoreOrdersSecurityBearingChanges(t *testing.T) {
	source := DefaultConfig()
	destination := source.Clone()
	destination.RejectForeignRekey = false
	destination.MaxFeeMicroAlgos = 1_000
	destination.AlwaysReviewWarnings = true
	destination.AutoApproveSelfNoOpTransfer = true

	sourceProjection, err := NormalizeForRestoreDiff(source, "signer", []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff(source) error = %v", err)
	}
	destinationProjection, err := NormalizeForRestoreDiff(destination, "signer", []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff(destination) error = %v", err)
	}
	comparison := DiffForRestore(sourceProjection, destinationProjection)
	if comparison.Status != RestoreComparisonDifferent {
		t.Fatalf("comparison status = %q, want different", comparison.Status)
	}
	wantCategories := []RestoreChangeCategory{
		RestoreCategoryHardRejects,
		RestoreCategoryCeilings,
		RestoreCategoryReview,
		RestoreCategoryAutoApproval,
	}
	if len(comparison.Changes) != len(wantCategories) {
		t.Fatalf("changes = %+v, want %d", comparison.Changes, len(wantCategories))
	}
	for i, want := range wantCategories {
		if comparison.Changes[i].Category != want {
			t.Fatalf("change %d category = %q, want %q", i, comparison.Changes[i].Category, want)
		}
	}
	if comparison.Changes[0].Path != "reject_foreign_rekey" {
		t.Fatalf("first change path = %q, want hard reject first", comparison.Changes[0].Path)
	}
}

func TestDiffForRestoreResolvesSelectorOverrides(t *testing.T) {
	source := DefaultConfig()
	destination := source.Clone()
	override := destination.Clone()
	override.KeyOverrides = nil
	override.MaxFeeMicroAlgos = 2_000
	destination.KeyOverrides = map[string]*Config{"selector": override}

	sourceProjection, err := NormalizeForRestoreDiff(source, "signer", []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff(source) error = %v", err)
	}
	destinationProjection, err := NormalizeForRestoreDiff(destination, "signer", []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff(destination) error = %v", err)
	}
	comparison := DiffForRestore(sourceProjection, destinationProjection)
	if comparison.Status != RestoreComparisonDifferent || len(comparison.Changes) != 1 {
		t.Fatalf("comparison = %+v, want one override change", comparison)
	}
	if comparison.Changes[0].Selector != "selector" ||
		comparison.Changes[0].Path != "max_fee_microalgos" {
		t.Fatalf("override change = %+v", comparison.Changes[0])
	}
}

func TestDiffForRestoreIdenticalAndCrossRoleUnavailable(t *testing.T) {
	cfg := DefaultConfig()
	projection, err := NormalizeForRestoreDiff(cfg, "signer", []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff() error = %v", err)
	}
	if got := DiffForRestore(projection, projection); got.Status != RestoreComparisonIdentical {
		t.Fatalf("identical comparison = %+v", got)
	}
	sentry := projection
	sentry.Role = "sentry"
	if got := DiffForRestore(projection, sentry); got.Status != RestoreComparisonUnavailable {
		t.Fatalf("cross-role comparison = %+v", got)
	}
}
