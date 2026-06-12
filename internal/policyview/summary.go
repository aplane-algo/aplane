// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyview

import (
	"sort"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
)

type AssetSetRow struct {
	Index        int
	Name         string
	NetworkCount int
	ASAIDCount   int
	Preview      string
}

func AssetSetRows(sets map[string]policy.StoredAssetSet) []AssetSetRow {
	names := sortedAssetSetNames(sets)
	rows := make([]AssetSetRow, 0, len(names))
	for i, name := range names {
		set := sets[name]
		rows = append(rows, AssetSetRow{
			Index:        i,
			Name:         name,
			NetworkCount: len(set),
			ASAIDCount:   AssetSetIDCount(set),
			Preview:      AssetSetPreview(set),
		})
	}
	return rows
}

func AssetSetIDCount(set policy.StoredAssetSet) int {
	var count int
	for _, ids := range set {
		count += len(ids)
	}
	return count
}

func AssetSetPreview(set policy.StoredAssetSet) string {
	if len(set) == 0 {
		return "-"
	}
	networks := SortedAssetSetNetworks(set)
	parts := make([]string, 0, len(networks))
	for _, network := range networks {
		parts = append(parts, network+":"+joinUint64s(set[network]))
	}
	return strings.Join(parts, " ")
}

func SortedAssetSetNetworks(set policy.StoredAssetSet) []string {
	networks := make([]string, 0, len(set))
	for network := range set {
		networks = append(networks, network)
	}
	sort.Strings(networks)
	return networks
}

func sortedAssetSetNames(sets map[string]policy.StoredAssetSet) []string {
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func joinUint64s(ids []uint64) string {
	if len(ids) == 0 {
		return "-"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatUint(id, 10)
	}
	return strings.Join(parts, ",")
}
