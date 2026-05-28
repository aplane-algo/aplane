// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyview

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

func TestTransferGuardGroupsMergeAdjacentRoutesWithSameMovementShape(t *testing.T) {
	closeAllow := true
	routes := []policy.StoredTransferRoute{
		{
			ID:           "test_algo",
			Description:  "Test payments",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"self"},
			Close:        policy.StoredRoutePermission{Allow: &closeAllow},
		},
		{
			ID:           "test_usdc",
			Description:  "Test payments",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "@usdc"}},
			Destinations: []string{"self"},
			Limits:       &policy.StoredAmountLimits{ReviewAbove: uint64Ptr(2_500_000)},
			Close:        policy.StoredRoutePermission{Allow: &closeAllow},
		},
	}

	groups := TransferGuardGroups(routes)

	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	group := groups[0]
	if group.ID != "test" {
		t.Fatalf("group ID = %q, want test", group.ID)
	}
	if group.Description != "Test payments" {
		t.Fatalf("description = %q, want Test payments", group.Description)
	}
	if got := strings.Join(group.Destinations, ","); got != "self" {
		t.Fatalf("destinations = %q, want self", got)
	}
	if len(group.AssetRows) != 2 || group.AssetRows[0].Asset != "algo" || group.AssetRows[1].Asset != "@usdc" {
		t.Fatalf("asset rows = %+v, want algo and @usdc", group.AssetRows)
	}
	if group.AssetRows[1].ReviewAbove == nil || *group.AssetRows[1].ReviewAbove != 2_500_000 {
		t.Fatalf("USDC review threshold = %v, want 2500000", group.AssetRows[1].ReviewAbove)
	}
}

func TestTransferGuardGroupsKeepAdvancedRoutesSeparate(t *testing.T) {
	routes := []policy.StoredTransferRoute{
		{
			ID:           "advanced",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}, {Raw: "10458941"}},
			Destinations: []string{"*"},
		},
		{
			ID:           "simple_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"*"},
		},
	}

	groups := TransferGuardGroups(routes)

	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if !groups[0].Advanced || !strings.Contains(groups[0].AdvancedReason, "exactly one asset") {
		t.Fatalf("advanced group = %+v, want exactly-one-asset reason", groups[0])
	}
	if groups[1].Advanced || len(groups[1].AssetRows) != 1 {
		t.Fatalf("simple group = %+v, want one editable asset row", groups[1])
	}
}

func TestBuildPolicyViewModelSummarizesFieldsAndCollections(t *testing.T) {
	enabled := true
	rejectForeignRekey := false
	stored := &policy.StoredConfig{
		RejectForeignRekey: &rejectForeignRekey,
		TransferPolicy: &policy.StoredTransferPolicy{
			SchemaVersion:       1,
			Enabled:             &enabled,
			BlockedDestinations: []string{"ADDR..."},
			AssetSets: map[string]policy.StoredAssetSet{
				"usdc": {"testnet": []uint64{10458941}},
			},
			Routes: []policy.StoredTransferRoute{
				{
					ID:           "test_algo",
					Networks:     []string{"testnet"},
					Sources:      []string{"*"},
					Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
					Destinations: []string{"self"},
				},
			},
		},
		KeyTypeOverrides: map[string]*policy.StoredConfig{
			"ed25519": {},
		},
	}

	model := Build(stored, "policy yaml")

	if model.TransferSummary != "enabled=true routes=1" {
		t.Fatalf("TransferSummary = %q, want enabled=true routes=1", model.TransferSummary)
	}
	if len(model.TransferGuards) != 1 || model.TransferGuards[0].ID != "test" {
		t.Fatalf("TransferGuards = %+v, want one test guard", model.TransferGuards)
	}
	if len(model.AssetSets) != 1 || model.AssetSets[0].Preview != "testnet:10458941" {
		t.Fatalf("AssetSets = %+v, want testnet USDC preview", model.AssetSets)
	}
	if len(model.BlockedDestinations) != 1 || model.BlockedDestinations[0] != "ADDR..." {
		t.Fatalf("BlockedDestinations = %+v, want ADDR...", model.BlockedDestinations)
	}
	if len(model.KeyTypeOverrides) != 1 || model.KeyTypeOverrides[0] != "ed25519" {
		t.Fatalf("KeyTypeOverrides = %+v, want ed25519", model.KeyTypeOverrides)
	}
	if got := model.Fields[0]; got.Key != "reject_foreign_rekey" || got.Value != "false" || got.Source != "explicit" {
		t.Fatalf("first field = %+v, want explicit reject_foreign_rekey=false", got)
	}
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}
