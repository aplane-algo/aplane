// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

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

func TestDiffForRestoreReportsScalarAndThresholdChanges(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(source, destination *Config)
		wantPath string
	}{
		{
			name: "remove hard reject",
			mutate: func(source, destination *Config) {
				source.RejectAssetClose = true
				destination.RejectAssetClose = false
			},
			wantPath: "reject_asset_close",
		},
		{
			name: "add hard reject",
			mutate: func(source, destination *Config) {
				source.RejectAssetClose = false
				destination.RejectAssetClose = true
			},
			wantPath: "reject_asset_close",
		},
		{
			name: "raise fee ceiling",
			mutate: func(source, destination *Config) {
				source.MaxFeeMicroAlgos = 1_000
				destination.MaxFeeMicroAlgos = 2_000
			},
			wantPath: "max_fee_microalgos",
		},
		{
			name: "lower fee ceiling",
			mutate: func(source, destination *Config) {
				source.MaxFeeMicroAlgos = 2_000
				destination.MaxFeeMicroAlgos = 1_000
			},
			wantPath: "max_fee_microalgos",
		},
		{
			name: "remove payment ceiling",
			mutate: func(source, destination *Config) {
				source.MaxAlgoPayments["mainnet"] = 1_000
				delete(destination.MaxAlgoPayments, "mainnet")
			},
			wantPath: "max_algo_payments",
		},
		{
			name: "remove warning review",
			mutate: func(source, destination *Config) {
				source.AlwaysReviewWarnings = true
				destination.AlwaysReviewWarnings = false
			},
			wantPath: "always_review_warnings",
		},
		{
			name: "add warning review",
			mutate: func(source, destination *Config) {
				source.AlwaysReviewWarnings = false
				destination.AlwaysReviewWarnings = true
			},
			wantPath: "always_review_warnings",
		},
		{
			name: "raise review threshold",
			mutate: func(source, destination *Config) {
				source.ReviewAlgoPayments["mainnet"] = 1_000
				destination.ReviewAlgoPayments["mainnet"] = 2_000
			},
			wantPath: "review_algo_payments",
		},
		{
			name: "enable explicit auto approval",
			mutate: func(source, destination *Config) {
				source.AutoApproveSelfNoOpTransfer = false
				destination.AutoApproveSelfNoOpTransfer = true
			},
			wantPath: "auto_approve_self_noop_transfer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := DefaultConfig()
			destination := DefaultConfig()
			tt.mutate(source, destination)
			comparison := compareRestoreConfigs(t, "signer", source, destination)
			if comparison.Status != RestoreComparisonDifferent ||
				len(comparison.Changes) != 1 ||
				comparison.Changes[0].Path != tt.wantPath {
				t.Fatalf("comparison = %+v, want one change at path %q",
					comparison, tt.wantPath)
			}
		})
	}
}

func TestDiffForRestoreReportsRoutingChanges(t *testing.T) {
	address := types.Address{1}
	tests := []struct {
		name   string
		mutate func(source, destination *Config)
	}{
		{
			name: "disable signer routing",
			mutate: func(_, destination *Config) {
				destination.TransferPolicy.Enabled = false
			},
		},
		{
			name: "tighten route miss",
			mutate: func(source, destination *Config) {
				source.TransferPolicy.OnNoRoute = TransferOnNoRouteReview
				destination.TransferPolicy.OnNoRoute = TransferOnNoRouteReject
			},
		},
		{
			name: "relax route miss",
			mutate: func(_, destination *Config) {
				destination.TransferPolicy.OnNoRoute = TransferOnNoRouteReview
			},
		},
		{
			name: "remove blocked destination",
			mutate: func(source, destination *Config) {
				source.TransferPolicy.BlockedDestinations[address] = struct{}{}
				delete(destination.TransferPolicy.BlockedDestinations, address)
			},
		},
		{
			name: "add blocked destination",
			mutate: func(source, destination *Config) {
				destination.TransferPolicy.BlockedDestinations[address] = struct{}{}
				delete(source.TransferPolicy.BlockedDestinations, address)
			},
		},
		{
			name: "broaden route destination",
			mutate: func(_, destination *Config) {
				destination.TransferPolicy.Routes[0].Destinations.Wildcard = true
				destination.TransferPolicy.Routes[0].Destinations.Direct = nil
			},
		},
		{
			name: "allow close",
			mutate: func(_, destination *Config) {
				destination.TransferPolicy.Routes[0].AllowClose = true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := restoreRoutingConfig(address)
			destination := source.Clone()
			tt.mutate(source, destination)
			comparison := compareRestoreConfigs(t, "signer", source, destination)
			if comparison.Status != RestoreComparisonDifferent {
				t.Fatalf("comparison = %+v, want a factual difference", comparison)
			}
		})
	}
}

func TestDiffForRestoreReportsRekeyEdgeChanges(t *testing.T) {
	sender := types.Address{1}
	firstTarget := types.Address{2}
	secondTarget := types.Address{3}
	tests := []struct {
		name               string
		sourceTargets      []types.Address
		destinationTargets []types.Address
	}{
		{
			name:               "add target",
			sourceTargets:      []types.Address{firstTarget},
			destinationTargets: []types.Address{firstTarget, secondTarget},
		},
		{
			name:               "remove target",
			sourceTargets:      []types.Address{firstTarget, secondTarget},
			destinationTargets: []types.Address{firstTarget},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := DefaultConfig()
			source.RekeyPolicy = restoreRekeyPolicy(sender, tt.sourceTargets)
			destination := DefaultConfig()
			destination.RekeyPolicy = restoreRekeyPolicy(sender, tt.destinationTargets)
			comparison := compareRestoreConfigs(t, "sentry", source, destination)
			if comparison.Status != RestoreComparisonDifferent ||
				len(comparison.Changes) != 1 ||
				comparison.Changes[0].Path != "rekey_policy.allowed" {
				t.Fatalf("comparison = %+v, want one rekey_policy.allowed change", comparison)
			}
		})
	}
}

func compareRestoreConfigs(
	t *testing.T,
	role string,
	source, destination *Config,
) RestorePolicyComparison {
	t.Helper()
	sourceProjection, err := NormalizeForRestoreDiff(source, role, []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff(source) error = %v", err)
	}
	destinationProjection, err := NormalizeForRestoreDiff(destination, role, []string{"selector"})
	if err != nil {
		t.Fatalf("NormalizeForRestoreDiff(destination) error = %v", err)
	}
	return DiffForRestore(sourceProjection, destinationProjection)
}

func restoreRekeyPolicy(sender types.Address, targets []types.Address) *RekeyPolicy {
	return &RekeyPolicy{Allowed: []CompiledRekeyRule{{
		Sender:  compiledRekeyAddressTerms{Direct: []types.Address{sender}},
		Targets: compiledRekeyAddressTerms{Direct: targets},
	}}}
}

func restoreRoutingConfig(destination types.Address) *Config {
	cfg := DefaultConfig()
	cfg.TransferPolicy = &TransferPolicy{
		Enabled:             true,
		OnNoRoute:           TransferOnNoRouteReject,
		CloseOnNoRoute:      TransferOnNoRouteReject,
		ClawbackOnNoRoute:   TransferOnNoRouteReject,
		BlockedDestinations: make(map[types.Address]struct{}),
		Routes: []CompiledTransferRoute{{
			ID:              "route",
			Enabled:         true,
			NetworkWildcard: true,
			Sources:         compiledAddressTerms{Wildcard: true},
			Assets:          compiledAssetTerms{Algo: true},
			Destinations:    compiledAddressTerms{Direct: []types.Address{destination}},
		}},
	}
	return cfg
}

func TestTransferRestoreFieldsProjectSetMembership(t *testing.T) {
	memberA := types.Address{1}
	memberB := types.Address{2}
	build := func(members []types.Address) *TransferPolicy {
		return &TransferPolicy{
			Enabled: true,
			AddressSets: map[string]compiledAddressSet{
				"treasury": {Flat: members},
			},
			AssetSets: map[string]compiledAssetSet{
				"stable": {ByNetwork: map[string][]uint64{"mainnet": {uint64(len(members))}}},
			},
			Routes: []CompiledTransferRoute{{
				ID:           "r1",
				Enabled:      true,
				Destinations: compiledAddressTerms{Sets: []string{"treasury"}},
				Assets:       compiledAssetTerms{Sets: []string{"stable"}},
			}},
		}
	}
	project := func(transfer *TransferPolicy) map[string]string {
		var fields []RestorePolicyField
		appendTransferRestoreFields(&fields, "default", transfer)
		out := make(map[string]string, len(fields))
		for _, field := range fields {
			out[field.Path] = field.Value
		}
		return out
	}

	source := project(build([]types.Address{memberA}))
	destination := project(build([]types.Address{memberA, memberB}))

	// The set names and routes are identical; only membership differs. The
	// projection must expose that difference or the diff reports identical
	// policies while the destination silently permits transfers to B.
	if _, ok := source["transfer_policy.address_sets.treasury"]; !ok {
		t.Fatalf("projection has no address-set membership field: %v", source)
	}
	if source["transfer_policy.address_sets.treasury"] == destination["transfer_policy.address_sets.treasury"] {
		t.Fatal("address-set membership change is invisible to the restore diff")
	}
	if source["transfer_policy.asset_sets.stable.by_network.mainnet"] == destination["transfer_policy.asset_sets.stable.by_network.mainnet"] {
		t.Fatal("asset-set membership change is invisible to the restore diff")
	}
}
