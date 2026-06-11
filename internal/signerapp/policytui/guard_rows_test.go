// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

func TestRouteToGuardRowProjectsSingleAssetRoute(t *testing.T) {
	enabled := true
	closeAllow := true
	route := policy.StoredTransferRoute{
		ID:           "m75_jhxb_algo",
		Description:  "M75 to JHXB ALGO",
		Enabled:      &enabled,
		Networks:     []string{"testnet"},
		Sources:      []string{"M75..."},
		Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
		Destinations: []string{"JHXB...", "self"},
		Limits: &policy.StoredAmountLimits{
			ReviewAbove: uint64Ptr(25_000_000),
			RejectAbove: uint64Ptr(50_000_000),
		},
		Close: policy.StoredRoutePermission{Allow: &closeAllow},
	}

	row := routeToGuardRow(3, route)

	if row.Advanced {
		t.Fatalf("row unexpectedly advanced: %s", row.AdvancedReason)
	}
	if row.Index != 3 || row.ID != "m75_jhxb_algo" || row.Asset != "algo" {
		t.Fatalf("row basics = index %d id %q asset %q", row.Index, row.ID, row.Asset)
	}
	if got := strings.Join(row.Networks, ","); got != "testnet" {
		t.Fatalf("networks = %q, want testnet", got)
	}
	if got := strings.Join(row.Sources, ","); got != "M75..." {
		t.Fatalf("sources = %q, want M75...", got)
	}
	if got := strings.Join(row.Destinations, ","); got != "JHXB...,self" {
		t.Fatalf("destinations = %q, want JHXB...,self", got)
	}
	if row.RejectAbove == nil || *row.RejectAbove != 50_000_000 {
		t.Fatalf("RejectAbove = %v, want 50000000", row.RejectAbove)
	}
	if row.CloseAllow == nil || !*row.CloseAllow {
		t.Fatalf("CloseAllow = %v, want true", row.CloseAllow)
	}
}

func TestGuardRowsAllowSpecificAssetsAndWildcardCatchall(t *testing.T) {
	routes := []policy.StoredTransferRoute{
		{
			ID:           "m75_jhxb_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"JHXB...", "self"},
			Limits:       &policy.StoredAmountLimits{RejectAbove: uint64Ptr(50_000_000)},
		},
		{
			ID:           "m75_jhxb_10458941",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "10458941"}},
			Destinations: []string{"JHXB...", "self"},
			Limits:       &policy.StoredAmountLimits{RejectAbove: uint64Ptr(5_000_000)},
		},
		{
			ID:           "m75_jhxb_other",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "*"}},
			Destinations: []string{"JHXB...", "self"},
		},
	}

	rows := transferGuardRows(routes)

	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	for i, wantAsset := range []string{"algo", "10458941", "*"} {
		if rows[i].Advanced {
			t.Fatalf("row %d advanced unexpectedly: %s", i, rows[i].AdvancedReason)
		}
		if rows[i].Asset != wantAsset {
			t.Fatalf("row %d asset = %q, want %q", i, rows[i].Asset, wantAsset)
		}
	}
	if rows[2].RejectAbove != nil {
		t.Fatalf("wildcard catchall reject threshold = %v, want nil", rows[2].RejectAbove)
	}
}

func TestTransferGuardGroupsMergeRoutesWithSameMovementShape(t *testing.T) {
	closeAllow := true
	routes := []policy.StoredTransferRoute{
		{
			ID:           "m75_jhxb_algo",
			Description:  "ALGO ceiling",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"JHXB...", "self"},
			Limits:       &policy.StoredAmountLimits{RejectAbove: uint64Ptr(50_000_000)},
			Close:        policy.StoredRoutePermission{Allow: &closeAllow},
		},
		{
			ID:           "m75_jhxb_usdc",
			Description:  "USDC ceiling",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "10458941"}},
			Destinations: []string{"JHXB...", "self"},
			Limits:       &policy.StoredAmountLimits{ReviewAbove: uint64Ptr(2_500_000), RejectAbove: uint64Ptr(5_000_000)},
			Close:        policy.StoredRoutePermission{Allow: &closeAllow},
		},
		{
			ID:           "m75_everywhere_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"*"},
		},
	}

	groups := transferGuardGroups(routes)

	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	first := groups[0]
	if first.Advanced {
		t.Fatalf("first group advanced unexpectedly: %s", first.AdvancedReason)
	}
	if len(first.RouteIndexes) != 2 || first.RouteIndexes[0] != 0 || first.RouteIndexes[1] != 1 {
		t.Fatalf("first route indexes = %v, want [0 1]", first.RouteIndexes)
	}
	if got := strings.Join(first.Destinations, ","); got != "JHXB...,self" {
		t.Fatalf("first destinations = %q, want JHXB...,self", got)
	}
	if first.Description != "" {
		t.Fatalf("first description = %q, want mixed descriptions to collapse", first.Description)
	}
	if len(first.AssetRows) != 2 {
		t.Fatalf("first asset rows = %d, want 2", len(first.AssetRows))
	}
	if first.AssetRows[0].Asset != "algo" || first.AssetRows[1].Asset != "10458941" {
		t.Fatalf("assets = %q, %q; want algo, 10458941", first.AssetRows[0].Asset, first.AssetRows[1].Asset)
	}
	if first.AssetRows[1].ReviewAbove == nil || *first.AssetRows[1].ReviewAbove != 2_500_000 {
		t.Fatalf("USDC review threshold = %v, want 2500000", first.AssetRows[1].ReviewAbove)
	}

	second := groups[1]
	if got := strings.Join(second.Destinations, ","); got != "*" {
		t.Fatalf("second destinations = %q, want *", got)
	}
	if second.ID != "m75_everywhere" || len(second.AssetRows) != 1 || second.AssetRows[0].Asset != "algo" {
		t.Fatalf("second group = %+v, want m75_everywhere algo", second)
	}
}

func TestTransferGuardGroupsUseRoutePrefixAsGuardName(t *testing.T) {
	routes := []policy.StoredTransferRoute{
		{
			ID:           "test_algo",
			Description:  "Test payments",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"self"},
		},
		{
			ID:           "test_usdc",
			Description:  "Test payments",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "@usdc"}},
			Destinations: []string{"self"},
		},
	}

	groups := transferGuardGroups(routes)

	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if groups[0].ID != "test" {
		t.Fatalf("guard ID = %q, want test", groups[0].ID)
	}
	if groups[0].Description != "Test payments" {
		t.Fatalf("guard description = %q, want Test payments", groups[0].Description)
	}
	if len(groups[0].AssetRows) != 2 || groups[0].AssetRows[1].Asset != "@usdc" {
		t.Fatalf("asset rows = %+v, want algo and @usdc", groups[0].AssetRows)
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
			ID:           "simple",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"*"},
		},
	}

	groups := transferGuardGroups(routes)

	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if !groups[0].Advanced {
		t.Fatal("first group Advanced = false, want true")
	}
	if len(groups[0].AssetRows) != 0 {
		t.Fatalf("advanced group asset rows = %d, want 0", len(groups[0].AssetRows))
	}
	if groups[1].Advanced || len(groups[1].AssetRows) != 1 {
		t.Fatalf("simple group = %+v, want one editable asset row", groups[1])
	}
}

func TestTransferGuardGroupsOnlyMergeAdjacentRoutes(t *testing.T) {
	routes := []policy.StoredTransferRoute{
		{
			ID:           "m75_jhxb_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"JHXB..."},
		},
		{
			ID:           "m75_elsewhere_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"*"},
		},
		{
			ID:           "m75_jhxb_10458941",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "10458941"}},
			Destinations: []string{"JHXB..."},
		},
	}

	groups := transferGuardGroups(routes)

	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(groups))
	}
	if groups[0].ID != "m75_jhxb" || groups[2].ID != "m75_jhxb" {
		t.Fatalf("non-adjacent same-shape routes were not preserved separately: %+v", groups)
	}
}

func TestTransferGuardGroupsDoNotMergeDuplicateAssets(t *testing.T) {
	routes := []policy.StoredTransferRoute{
		{
			ID:           "first_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"JHXB..."},
		},
		{
			ID:           "second_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"M75..."},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"JHXB..."},
		},
	}

	groups := transferGuardGroups(routes)

	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if groups[0].ID != "first" || groups[1].ID != "second" {
		t.Fatalf("duplicate-asset groups = %+v", groups)
	}
}

func TestGuardGroupToRoutesExpandsAssetRows(t *testing.T) {
	enabled := true
	closeAllow := false
	group := transferGuardGroup{
		ID:           "m75_jhxb",
		Description:  "M75 to JHXB",
		Enabled:      &enabled,
		Networks:     []string{"testnet"},
		Sources:      []string{"M75..."},
		Destinations: []string{"JHXB...", "self"},
		CloseAllow:   &closeAllow,
		AssetRows: []transferGuardAssetRow{
			{
				RouteIndex:  0,
				Asset:       "algo",
				RejectAbove: uint64Ptr(50_000_000),
			},
			{
				RouteIndex:  1,
				Asset:       "@usdc",
				ReviewAbove: uint64Ptr(2_500_000),
				RejectAbove: uint64Ptr(5_000_000),
			},
		},
	}
	existing := []policy.StoredTransferRoute{
		{ID: "m75_jhxb_algo", AssetSources: []string{"should be cleared"}},
		{ID: "m75_jhxb_usdc", LimitsByNetwork: map[string]policy.StoredAmountLimits{"testnet": {RejectAbove: uint64Ptr(1)}}},
	}

	routes, err := guardGroupToRoutes(group, existing)
	if err != nil {
		t.Fatalf("guardGroupToRoutes() error = %v", err)
	}

	if len(routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(routes))
	}
	if routes[0].ID != "m75_jhxb_algo" || routes[0].Description != "M75 to JHXB" {
		t.Fatalf("route 0 identity = %q/%q", routes[0].ID, routes[0].Description)
	}
	if got := joinAssetTerms(routes[0].Assets); got != "algo" {
		t.Fatalf("route 0 assets = %q, want algo", got)
	}
	if routes[0].Limits == nil || routes[0].Limits.RejectAbove == nil || *routes[0].Limits.RejectAbove != 50_000_000 {
		t.Fatalf("route 0 limits = %+v, want reject 50000000", routes[0].Limits)
	}
	if routes[1].ID != "m75_jhxb_usdc" || routes[1].Description != "M75 to JHXB" {
		t.Fatalf("route 1 identity = %q/%q", routes[1].ID, routes[1].Description)
	}
	if routes[1].LimitsByNetwork != nil || len(routes[0].AssetSources) != 0 {
		t.Fatalf("advanced fields survived: route0 asset_sources=%v route1 limits_by_network=%v", routes[0].AssetSources, routes[1].LimitsByNetwork)
	}
	if routes[1].Enabled == nil || !*routes[1].Enabled {
		t.Fatalf("route 1 enabled = %v, want true", routes[1].Enabled)
	}
	if routes[1].Close.Allow == nil || *routes[1].Close.Allow {
		t.Fatalf("route 1 close.allow = %v, want false", routes[1].Close.Allow)
	}
}

func TestGuardGroupToRoutesPreservesNonConventionRouteIDOnNoOp(t *testing.T) {
	group := transferGuardGroup{
		ID:           "treasury",
		Description:  "Treasury",
		Networks:     []string{"testnet"},
		Sources:      []string{"*"},
		Destinations: []string{"self"},
		AssetRows: []transferGuardAssetRow{{
			RouteIndex: 0,
			Asset:      "algo",
		}},
	}
	existing := []policy.StoredTransferRoute{{
		ID:           "treasury",
		Description:  "Treasury",
		Networks:     []string{"testnet"},
		Sources:      []string{"*"},
		Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
		Destinations: []string{"self"},
	}}

	routes, err := guardGroupToRoutes(group, existing)
	if err != nil {
		t.Fatalf("guardGroupToRoutes() error = %v", err)
	}
	if len(routes) != 1 || routes[0].ID != "treasury" {
		t.Fatalf("route IDs = %+v, want preserved treasury", routes)
	}
}

func TestGuardGroupToRoutesUsesConventionForRenamedGuard(t *testing.T) {
	group := transferGuardGroup{
		ID:           "operations",
		Description:  "Treasury",
		Networks:     []string{"testnet"},
		Sources:      []string{"*"},
		Destinations: []string{"self"},
		AssetRows: []transferGuardAssetRow{{
			RouteIndex: 0,
			Asset:      "algo",
		}},
	}
	existing := []policy.StoredTransferRoute{{
		ID:           "treasury",
		Description:  "Treasury",
		Networks:     []string{"testnet"},
		Sources:      []string{"*"},
		Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
		Destinations: []string{"self"},
	}}

	routes, err := guardGroupToRoutes(group, existing)
	if err != nil {
		t.Fatalf("guardGroupToRoutes() error = %v", err)
	}
	if len(routes) != 1 || routes[0].ID != "operations_algo" {
		t.Fatalf("route IDs = %+v, want operations_algo", routes)
	}
}

func TestGuardRowToRouteWritesOneAssetRoute(t *testing.T) {
	enabled := true
	closeAllow := false
	row := transferGuardRow{
		ID:           "m75_jhxb_usdc",
		Description:  "M75 to JHXB USDC",
		Enabled:      &enabled,
		Networks:     []string{"testnet"},
		Sources:      []string{"M75..."},
		Destinations: []string{"JHXB...", "self"},
		Asset:        "10458941",
		ReviewAbove:  uint64Ptr(2_500_000),
		RejectAbove:  uint64Ptr(5_000_000),
		CloseAllow:   &closeAllow,
	}

	route, err := guardRowToRoute(row, nil)
	if err != nil {
		t.Fatalf("guardRowToRoute() error = %v", err)
	}

	if route.ID != "m75_jhxb_usdc" {
		t.Fatalf("route ID = %q, want m75_jhxb_usdc", route.ID)
	}
	if got := joinAssetTerms(route.Assets); got != "10458941" {
		t.Fatalf("assets = %q, want 10458941", got)
	}
	if route.Limits == nil || route.Limits.ReviewAbove == nil || *route.Limits.ReviewAbove != 2_500_000 ||
		route.Limits.RejectAbove == nil || *route.Limits.RejectAbove != 5_000_000 {
		t.Fatalf("limits = %+v, want review/reject thresholds", route.Limits)
	}
	if route.Clawback.Allow != nil || len(route.AssetSources) != 0 || len(route.LimitsByNetwork) != 0 {
		t.Fatalf("route kept advanced fields: clawback=%v asset_sources=%v limits_by_network=%v",
			route.Clawback.Allow, route.AssetSources, route.LimitsByNetwork)
	}
}

func TestRouteToGuardRowMarksAdvancedShapes(t *testing.T) {
	tests := []struct {
		name  string
		route policy.StoredTransferRoute
		want  string
	}{
		{
			name: "multiple assets",
			route: policy.StoredTransferRoute{
				ID:           "mixed",
				Networks:     []string{"testnet"},
				Sources:      []string{"*"},
				Assets:       []policy.StoredAssetTerm{{Raw: "algo"}, {Raw: "10458941"}},
				Destinations: []string{"*"},
			},
			want: "exactly one asset",
		},
		{
			name: "limits by network",
			route: policy.StoredTransferRoute{
				ID:              "network_limits",
				Networks:        []string{"mainnet", "testnet"},
				Sources:         []string{"*"},
				Assets:          []policy.StoredAssetTerm{{Raw: "@stablecoins"}},
				Destinations:    []string{"*"},
				LimitsByNetwork: map[string]policy.StoredAmountLimits{"mainnet": {RejectAbove: uint64Ptr(5)}, "testnet": {RejectAbove: uint64Ptr(7)}},
			},
			want: "limits_by_network",
		},
		{
			name: "wildcard asset limits",
			route: policy.StoredTransferRoute{
				ID:           "wildcard_limits",
				Networks:     []string{"testnet"},
				Sources:      []string{"*"},
				Assets:       []policy.StoredAssetTerm{{Raw: "*"}},
				Destinations: []string{"*"},
				Limits:       &policy.StoredAmountLimits{RejectAbove: uint64Ptr(5)},
			},
			want: "asset set or wildcard",
		},
		{
			name: "asa limits with wildcard networks",
			route: policy.StoredTransferRoute{
				ID:           "asa_wildcard_network_limits",
				Networks:     []string{"*"},
				Sources:      []string{"*"},
				Assets:       []policy.StoredAssetTerm{{Raw: "10458941"}},
				Destinations: []string{"*"},
				Limits:       &policy.StoredAmountLimits{RejectAbove: uint64Ptr(5)},
			},
			want: "one concrete network",
		},
		{
			name: "clawback source",
			route: policy.StoredTransferRoute{
				ID:           "clawback",
				Networks:     []string{"testnet"},
				Sources:      []string{"*"},
				AssetSources: []string{"*"},
				Assets:       []policy.StoredAssetTerm{{Raw: "10458941"}},
				Destinations: []string{"*"},
				Clawback:     policy.StoredRoutePermission{Allow: boolPtr(true)},
			},
			want: "asset_sources",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := routeToGuardRow(0, tc.route)
			if !row.Advanced {
				t.Fatal("Advanced = false, want true")
			}
			if !strings.Contains(row.AdvancedReason, tc.want) {
				t.Fatalf("AdvancedReason = %q, want containing %q", row.AdvancedReason, tc.want)
			}
		})
	}
}

func TestRouteToGuardRowCollapsesUniformLimitsByNetwork(t *testing.T) {
	route := policy.StoredTransferRoute{
		ID:           "stablecoin",
		Networks:     []string{"mainnet", "testnet"},
		Sources:      []string{"*"},
		Assets:       []policy.StoredAssetTerm{{Raw: "@usdc"}},
		Destinations: []string{"*"},
		LimitsByNetwork: map[string]policy.StoredAmountLimits{
			"mainnet": {RejectAbove: uint64Ptr(5_000_000)},
			"testnet": {RejectAbove: uint64Ptr(5_000_000)},
		},
	}

	row := routeToGuardRow(0, route)

	if row.Advanced {
		t.Fatalf("row advanced unexpectedly: %s", row.AdvancedReason)
	}
	if row.RejectAbove == nil || *row.RejectAbove != 5_000_000 {
		t.Fatalf("RejectAbove = %v, want 5000000", row.RejectAbove)
	}
}

func TestRouteToGuardRowKeepsNonUniformLimitsByNetworkAdvanced(t *testing.T) {
	route := policy.StoredTransferRoute{
		ID:           "stablecoin",
		Networks:     []string{"mainnet", "testnet"},
		Sources:      []string{"*"},
		Assets:       []policy.StoredAssetTerm{{Raw: "@usdc"}},
		Destinations: []string{"*"},
		LimitsByNetwork: map[string]policy.StoredAmountLimits{
			"mainnet": {RejectAbove: uint64Ptr(5_000_000)},
			"testnet": {RejectAbove: uint64Ptr(7_000_000)},
		},
	}

	row := routeToGuardRow(0, route)

	if !row.Advanced {
		t.Fatal("Advanced = false, want true")
	}
	if !strings.Contains(row.AdvancedReason, "limits_by_network") {
		t.Fatalf("AdvancedReason = %q, want limits_by_network", row.AdvancedReason)
	}
}

func TestGuardRowToRouteWritesAssetSetLimitsByNetwork(t *testing.T) {
	row := transferGuardRow{
		ID:           "stablecoin",
		Networks:     []string{"mainnet", "testnet"},
		Sources:      []string{"*"},
		Destinations: []string{"*"},
		Asset:        "@usdc",
		RejectAbove:  uint64Ptr(5_000_000),
	}

	route, err := guardRowToRoute(row, nil)
	if err != nil {
		t.Fatalf("guardRowToRoute() error = %v", err)
	}

	if route.Limits != nil {
		t.Fatalf("Limits = %+v, want nil when asset set spans networks", route.Limits)
	}
	if len(route.LimitsByNetwork) != 2 {
		t.Fatalf("LimitsByNetwork = %+v, want two network entries", route.LimitsByNetwork)
	}
	for _, network := range []string{"mainnet", "testnet"} {
		limits := route.LimitsByNetwork[network]
		if limits.RejectAbove == nil || *limits.RejectAbove != 5_000_000 {
			t.Fatalf("%s reject = %+v, want 5000000", network, limits.RejectAbove)
		}
	}
}

func boolPtr(v bool) *bool {
	return &v
}
