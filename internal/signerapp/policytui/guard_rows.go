// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyview"
)

type transferGuardRow = policyview.TransferGuardRow
type transferGuardAssetRow = policyview.TransferGuardAssetRow
type transferGuardGroup = policyview.TransferGuardGroup

func transferGuardGroups(routes []policy.StoredTransferRoute) []transferGuardGroup {
	return policyview.TransferGuardGroups(routes)
}

func guardNameFromRoute(routeID, asset string) string {
	return policyview.GuardNameFromRoute(routeID, asset)
}

func guardGroupToRoutes(group transferGuardGroup, existing []policy.StoredTransferRoute) ([]policy.StoredTransferRoute, error) {
	if group.Advanced {
		return nil, fmt.Errorf("advanced route is YAML-only: %s", group.AdvancedReason)
	}
	routes := make([]policy.StoredTransferRoute, 0, len(group.AssetRows))
	for _, assetRow := range group.AssetRows {
		var existingRoute *policy.StoredTransferRoute
		if assetRow.RouteIndex >= 0 && assetRow.RouteIndex < len(existing) {
			existingRoute = &existing[assetRow.RouteIndex]
		}
		routeID := assetRow.RouteID
		if routeID == "" {
			routeID = guardRouteIDForExisting(group.ID, assetRow.Asset, existingRoute)
		}
		row := transferGuardRow{
			Index:        assetRow.RouteIndex,
			ID:           routeID,
			Description:  group.Description,
			Enabled:      cloneBoolPtr(group.Enabled),
			Networks:     append([]string(nil), group.Networks...),
			Sources:      append([]string(nil), group.Sources...),
			Destinations: append([]string(nil), group.Destinations...),
			Asset:        assetRow.Asset,
			ReviewAbove:  cloneUint64Ptr(assetRow.ReviewAbove),
			RejectAbove:  cloneUint64Ptr(assetRow.RejectAbove),
			CloseAllow:   cloneBoolPtr(group.CloseAllow),
		}
		route, err := guardRowToRoute(row, existingRoute)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func guardRowToRoute(row transferGuardRow, existing *policy.StoredTransferRoute) (policy.StoredTransferRoute, error) {
	if row.Advanced {
		return policy.StoredTransferRoute{}, fmt.Errorf("advanced route is YAML-only: %s", row.AdvancedReason)
	}
	if row.Asset == "" {
		return policy.StoredTransferRoute{}, fmt.Errorf("asset is required")
	}

	var route policy.StoredTransferRoute
	if existing != nil {
		route = cloneRoute(*existing)
	}
	route.ID = row.ID
	route.Description = row.Description
	route.Enabled = cloneBoolPtr(row.Enabled)
	route.Networks = append([]string(nil), row.Networks...)
	route.Sources = append([]string(nil), row.Sources...)
	route.AssetSources = nil
	route.Assets = []policy.StoredAssetTerm{{Raw: row.Asset}}
	route.Destinations = append([]string(nil), row.Destinations...)
	route.Close = policy.StoredRoutePermission{Allow: cloneBoolPtr(row.CloseAllow)}
	route.Clawback = policy.StoredRoutePermission{}
	route.LimitsByNetwork = nil
	if row.ReviewAbove != nil || row.RejectAbove != nil {
		limits := policy.StoredAmountLimits{
			ReviewAbove: cloneUint64Ptr(row.ReviewAbove),
			RejectAbove: cloneUint64Ptr(row.RejectAbove),
		}
		if _, ok := assetSetNameFromGuardAsset(row.Asset); ok && len(concreteGuardNetworks(row.Networks)) > 1 {
			route.Limits = nil
			route.LimitsByNetwork = make(map[string]policy.StoredAmountLimits)
			for _, network := range concreteGuardNetworks(row.Networks) {
				route.LimitsByNetwork[network] = cloneStoredAmountLimits(limits)
			}
		} else {
			route.Limits = &limits
		}
	} else {
		route.Limits = nil
	}
	return route, nil
}

func cloneStoredAmountLimits(limits policy.StoredAmountLimits) policy.StoredAmountLimits {
	return policy.StoredAmountLimits{
		ReviewAbove: cloneUint64Ptr(limits.ReviewAbove),
		RejectAbove: cloneUint64Ptr(limits.RejectAbove),
	}
}

func guardRouteID(guardName, asset string) string {
	return strings.TrimSpace(guardName) + "_" + policyview.GuardAssetIDPart(asset)
}

func guardRouteIDForExisting(guardName, asset string, existing *policy.StoredTransferRoute) string {
	generated := guardRouteID(guardName, asset)
	if existing == nil || len(existing.Assets) != 1 {
		return generated
	}
	oldAsset := strings.TrimSpace(existing.Assets[0].Raw)
	if strings.TrimSpace(asset) != oldAsset {
		return generated
	}
	oldGuardName := policyview.GuardNameFromRoute(existing.ID, oldAsset)
	if strings.TrimSpace(guardName) != oldGuardName {
		return generated
	}
	if existing.ID != guardRouteID(oldGuardName, oldAsset) {
		return existing.ID
	}
	return generated
}

func cloneBoolPtr(v *bool) *bool {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneUint64Ptr(v *uint64) *uint64 {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}
