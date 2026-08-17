// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyview builds read-only policy presentation models shared by
// apadmin's guided policy editors.
package policyview

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
)

type TransferGuardRow struct {
	Index          int
	ID             string
	Description    string
	Enabled        *bool
	Networks       []string
	Sources        []string
	Destinations   []string
	Asset          string
	ReviewAbove    *uint64
	RejectAbove    *uint64
	CloseAllow     *bool
	Advanced       bool
	AdvancedReason string
}

type TransferGuardAssetRow struct {
	RouteIndex  int
	RouteID     string
	Asset       string
	ReviewAbove *uint64
	RejectAbove *uint64
}

type TransferGuardGroup struct {
	Index          int
	RouteIndexes   []int
	ID             string
	Description    string
	Enabled        *bool
	Networks       []string
	Sources        []string
	Destinations   []string
	CloseAllow     *bool
	AssetRows      []TransferGuardAssetRow
	Advanced       bool
	AdvancedReason string
}

func TransferGuardRows(routes []policy.StoredTransferRoute) []TransferGuardRow {
	rows := make([]TransferGuardRow, 0, len(routes))
	for i, route := range routes {
		rows = append(rows, RouteToGuardRow(i, route))
	}
	return rows
}

func TransferGuardGroups(routes []policy.StoredTransferRoute) []TransferGuardGroup {
	groups := make([]TransferGuardGroup, 0, len(routes))
	lastKey := ""
	lastGroupIndex := -1
	for i, route := range routes {
		row := RouteToGuardRow(i, route)
		if row.Advanced {
			groups = append(groups, TransferGuardGroup{
				Index:          len(groups),
				RouteIndexes:   []int{i},
				ID:             row.ID,
				Description:    row.Description,
				Enabled:        cloneBoolPtr(row.Enabled),
				Networks:       append([]string(nil), row.Networks...),
				Sources:        append([]string(nil), row.Sources...),
				Destinations:   append([]string(nil), row.Destinations...),
				CloseAllow:     cloneBoolPtr(row.CloseAllow),
				Advanced:       true,
				AdvancedReason: row.AdvancedReason,
			})
			lastKey = ""
			lastGroupIndex = -1
			continue
		}

		key := guardGroupKey(row)
		groupIndex := lastGroupIndex
		if key != lastKey || groupIndex < 0 || guardGroupHasAsset(groups[groupIndex], row.Asset) {
			groupIndex = len(groups)
			groups = append(groups, TransferGuardGroup{
				Index:        groupIndex,
				ID:           GuardNameFromRoute(row.ID, row.Asset),
				Description:  row.Description,
				Enabled:      cloneBoolPtr(row.Enabled),
				Networks:     append([]string(nil), row.Networks...),
				Sources:      append([]string(nil), row.Sources...),
				Destinations: append([]string(nil), row.Destinations...),
				CloseAllow:   cloneBoolPtr(row.CloseAllow),
			})
		}
		lastKey = key
		lastGroupIndex = groupIndex
		group := &groups[groupIndex]
		group.RouteIndexes = append(group.RouteIndexes, i)
		if group.Description != row.Description {
			group.Description = ""
		}
		group.AssetRows = append(group.AssetRows, TransferGuardAssetRow{
			RouteIndex:  i,
			RouteID:     row.ID,
			Asset:       row.Asset,
			ReviewAbove: cloneUint64Ptr(row.ReviewAbove),
			RejectAbove: cloneUint64Ptr(row.RejectAbove),
		})
	}
	for i := range groups {
		if !groups[i].Advanced {
			groups[i].ID = guardNameFromGroupRoutes(groups[i], routes)
		}
	}
	return groups
}

func RouteToGuardRow(index int, route policy.StoredTransferRoute) TransferGuardRow {
	row := TransferGuardRow{
		Index:        index,
		ID:           route.ID,
		Description:  route.Description,
		Enabled:      cloneBoolPtr(route.Enabled),
		Networks:     append([]string(nil), route.Networks...),
		Sources:      append([]string(nil), route.Sources...),
		Destinations: append([]string(nil), route.Destinations...),
		CloseAllow:   cloneBoolPtr(route.Close.Allow),
	}
	if len(route.Assets) == 1 {
		row.Asset = route.Assets[0].Raw
	}
	if route.Limits != nil {
		row.ReviewAbove = cloneUint64Ptr(route.Limits.ReviewAbove)
		row.RejectAbove = cloneUint64Ptr(route.Limits.RejectAbove)
	} else if limits, ok := CollapseRouteLimitsByNetwork(route); ok {
		row.ReviewAbove = cloneUint64Ptr(limits.ReviewAbove)
		row.RejectAbove = cloneUint64Ptr(limits.RejectAbove)
	}
	row.Advanced, row.AdvancedReason = guardRowAdvancedReason(route)
	return row
}

func GuardNameFromRoute(routeID, asset string) string {
	if name, ok := trimRouteAssetSuffix(routeID, asset); ok && name != "" {
		return name
	}
	if name, ok := trimRouteLastSegment(routeID); ok && name != "" {
		return name
	}
	return strings.TrimSpace(routeID)
}

func GuardAssetIDPart(asset string) string {
	asset = strings.ToLower(strings.TrimSpace(asset))
	if asset == "" {
		return "asset"
	}
	var b strings.Builder
	for _, r := range asset {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "asset"
	}
	return out
}

func CollapseRouteLimitsByNetwork(route policy.StoredTransferRoute) (policy.StoredAmountLimits, bool) {
	if len(route.LimitsByNetwork) == 0 || route.Limits != nil {
		return policy.StoredAmountLimits{}, false
	}
	networks := concreteGuardNetworks(route.Networks)
	if len(networks) == 0 || len(networks) != len(route.Networks) {
		return policy.StoredAmountLimits{}, false
	}
	var first policy.StoredAmountLimits
	for i, network := range networks {
		limits, ok := route.LimitsByNetwork[network]
		if !ok {
			return policy.StoredAmountLimits{}, false
		}
		if i == 0 {
			first = limits
			continue
		}
		if !uint64PtrEqual(first.ReviewAbove, limits.ReviewAbove) ||
			!uint64PtrEqual(first.RejectAbove, limits.RejectAbove) {
			return policy.StoredAmountLimits{}, false
		}
	}
	return first, true
}

func guardGroupHasAsset(group TransferGuardGroup, asset string) bool {
	for _, row := range group.AssetRows {
		if row.Asset == asset {
			return true
		}
	}
	return false
}

func guardRowAdvancedReason(route policy.StoredTransferRoute) (bool, string) {
	if len(route.Assets) != 1 {
		return true, "requires exactly one asset term for guard editing"
	}
	if len(route.LimitsByNetwork) > 0 {
		if _, ok := CollapseRouteLimitsByNetwork(route); !ok {
			return true, "uses non-uniform limits_by_network"
		}
	}
	if advanced, reason := guardRouteLimitAdvancedReason(route); advanced {
		return true, reason
	}
	if len(route.AssetSources) > 0 {
		return true, "uses clawback asset_sources"
	}
	if route.Clawback.Allow != nil {
		return true, "uses clawback.allow"
	}
	return false, ""
}

func guardRouteLimitAdvancedReason(route policy.StoredTransferRoute) (bool, string) {
	if !routeHasAmountLimits(route) || len(route.Assets) != 1 {
		return false, ""
	}
	asset := strings.TrimSpace(route.Assets[0].Raw)
	if isAlgoGuardAsset(asset) {
		return false, ""
	}
	if _, ok := concreteASAIDFromGuardAsset(asset); ok {
		if len(concreteGuardNetworks(route.Networks)) != 1 {
			return true, "uses ASA amount limits outside one concrete network"
		}
		return false, ""
	}
	if _, ok := assetSetNameFromGuardAsset(asset); ok {
		if len(concreteGuardNetworks(route.Networks)) == 0 {
			return true, "uses asset-set amount limits without concrete networks"
		}
		return false, ""
	}
	return true, "uses amount limits with asset set or wildcard"
}

func routeHasAmountLimits(route policy.StoredTransferRoute) bool {
	return route.Limits != nil && (route.Limits.ReviewAbove != nil || route.Limits.RejectAbove != nil)
}

func IsAlgoGuardAsset(asset string) bool {
	return strings.EqualFold(strings.TrimSpace(asset), "algo")
}

func ConcreteASAIDFromGuardAsset(asset string) (uint64, bool) {
	asset = strings.TrimSpace(asset)
	if asset == "" {
		return 0, false
	}
	if strings.HasPrefix(strings.ToLower(asset), "asa:") {
		asset = strings.TrimSpace(asset[4:])
	}
	id, err := strconv.ParseUint(asset, 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

func AssetSetNameFromGuardAsset(asset string) (string, bool) {
	asset = strings.TrimSpace(asset)
	if !strings.HasPrefix(asset, "@") || len(asset) == 1 {
		return "", false
	}
	return strings.TrimSpace(asset[1:]), true
}

func ConcreteGuardNetworks(networks []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, network := range networks {
		network = strings.TrimSpace(network)
		if network == "" || network == "*" {
			continue
		}
		if _, ok := seen[network]; ok {
			continue
		}
		seen[network] = struct{}{}
		out = append(out, network)
	}
	return out
}

func isAlgoGuardAsset(asset string) bool {
	return IsAlgoGuardAsset(asset)
}

func concreteASAIDFromGuardAsset(asset string) (uint64, bool) {
	return ConcreteASAIDFromGuardAsset(asset)
}

func assetSetNameFromGuardAsset(asset string) (string, bool) {
	return AssetSetNameFromGuardAsset(asset)
}

func concreteGuardNetworks(networks []string) []string {
	return ConcreteGuardNetworks(networks)
}

func guardGroupKey(row TransferGuardRow) string {
	return strings.Join([]string{
		GuardNameFromRoute(row.ID, row.Asset),
		boolPtrKey(row.Enabled),
		termListKey(row.Networks),
		termListKey(row.Sources),
		termListKey(row.Destinations),
		boolPtrKey(row.CloseAllow),
	}, "\x1f")
}

func guardNameFromGroupRoutes(group TransferGuardGroup, routes []policy.StoredTransferRoute) string {
	if len(group.RouteIndexes) == 0 {
		return strings.TrimSpace(group.ID)
	}
	if name, ok := commonAssetSuffixGuardName(group, routes); ok {
		return name
	}
	if len(group.RouteIndexes) > 1 {
		if name, ok := commonLastSegmentGuardName(group, routes); ok {
			return name
		}
	}
	index := group.RouteIndexes[0]
	if index >= 0 && index < len(routes) {
		return strings.TrimSpace(routes[index].ID)
	}
	return strings.TrimSpace(group.ID)
}

func commonAssetSuffixGuardName(group TransferGuardGroup, routes []policy.StoredTransferRoute) (string, bool) {
	name := ""
	for i, index := range group.RouteIndexes {
		if index < 0 || index >= len(routes) || i >= len(group.AssetRows) {
			return "", false
		}
		candidate, ok := trimRouteAssetSuffix(routes[index].ID, group.AssetRows[i].Asset)
		if !ok || candidate == "" {
			return "", false
		}
		if name == "" {
			name = candidate
			continue
		}
		if candidate != name {
			return "", false
		}
	}
	return name, name != ""
}

func commonLastSegmentGuardName(group TransferGuardGroup, routes []policy.StoredTransferRoute) (string, bool) {
	name := ""
	for _, index := range group.RouteIndexes {
		if index < 0 || index >= len(routes) {
			return "", false
		}
		candidate, ok := trimRouteLastSegment(routes[index].ID)
		if !ok || candidate == "" {
			return "", false
		}
		if name == "" {
			name = candidate
			continue
		}
		if candidate != name {
			return "", false
		}
	}
	return name, name != ""
}

func trimRouteAssetSuffix(routeID, asset string) (string, bool) {
	routeID = strings.TrimSpace(routeID)
	suffix := "_" + GuardAssetIDPart(asset)
	if suffix == "_" || !strings.HasSuffix(routeID, suffix) {
		return "", false
	}
	return strings.TrimSuffix(routeID, suffix), true
}

func trimRouteLastSegment(routeID string) (string, bool) {
	routeID = strings.TrimSpace(routeID)
	index := strings.LastIndex(routeID, "_")
	if index <= 0 {
		return "", false
	}
	return routeID[:index], true
}

func termListKey(terms []string) string {
	if len(terms) == 0 {
		return "0:"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%d:", len(terms)))
	for _, term := range terms {
		b.WriteString(fmt.Sprintf("%d:", len(term)))
		b.WriteString(term)
		b.WriteByte('\x1e')
	}
	return b.String()
}

func boolPtrKey(v *bool) string {
	if v == nil {
		return "nil"
	}
	if *v {
		return "true"
	}
	return "false"
}

func uint64PtrEqual(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
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
