// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyview"
)

type assetSetRow = policyview.AssetSetRow

type assetSetEditRow struct {
	Network string
	ASAIDs  string
}

func transferAssetSetRows(sets map[string]policy.StoredAssetSet) []assetSetRow {
	return policyview.AssetSetRows(sets)
}

func defaultAssetSets() map[string]policy.StoredAssetSet {
	usdc := defaultUSDCAssetSet()
	if len(usdc) == 0 {
		return nil
	}
	return map[string]policy.StoredAssetSet{
		"usdc": usdc,
	}
}

func defaultUSDCAssetSet() policy.StoredAssetSet {
	out := make(policy.StoredAssetSet)
	for _, network := range []string{"mainnet", "testnet"} {
		meta, ok := asa.BuiltinMetadataByRef(network, "usdc")
		if !ok {
			continue
		}
		out[network] = []uint64{meta.AssetID}
	}
	return out
}

func cloneAssetSet(set policy.StoredAssetSet) policy.StoredAssetSet {
	if set == nil {
		return nil
	}
	out := make(policy.StoredAssetSet, len(set))
	for network, ids := range set {
		out[network] = append([]uint64(nil), ids...)
	}
	return out
}

func assetSetIndexByName(rows []assetSetRow, name string) int {
	for i, row := range rows {
		if row.Name == name {
			return i
		}
	}
	return 0
}

func validateAssetSetName(name string) error {
	if name == "" {
		return fmt.Errorf("asset set name is required")
	}
	for i, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("invalid asset set name %q at character %d", name, i)
	}
	return nil
}

func assetSetToEditRows(set policy.StoredAssetSet) []assetSetEditRow {
	networks := sortedAssetSetNetworks(set)
	rows := make([]assetSetEditRow, 0, len(networks))
	for _, network := range networks {
		rows = append(rows, assetSetEditRow{
			Network: network,
			ASAIDs:  joinUint64s(set[network]),
		})
	}
	return rows
}

func editRowsToAssetSet(rows []assetSetEditRow) (policy.StoredAssetSet, error) {
	out := make(policy.StoredAssetSet, len(rows))
	for i, row := range rows {
		network := strings.TrimSpace(row.Network)
		if network == "" {
			return nil, fmt.Errorf("network row %d network is required", i+1)
		}
		if network == "*" {
			return nil, fmt.Errorf("network row %d cannot use *", i+1)
		}
		if _, ok := out[network]; ok {
			return nil, fmt.Errorf("network row %d duplicates network %s", i+1, network)
		}
		ids, err := parseAssetSetIDs(row.ASAIDs)
		if err != nil {
			return nil, fmt.Errorf("network row %d ASA IDs: %w", i+1, err)
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("network row %d must include at least one ASA ID", i+1)
		}
		out[network] = ids
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("asset set must include at least one network")
	}
	return out, nil
}

func sortedAssetSetNetworks(set policy.StoredAssetSet) []string {
	return policyview.SortedAssetSetNetworks(set)
}

func parseAssetSetIDs(raw string) ([]uint64, error) {
	terms := parseCSV(raw)
	seen := make(map[uint64]struct{}, len(terms))
	for _, term := range terms {
		id, err := parseAssetSetID(term)
		if err != nil {
			return nil, err
		}
		seen[id] = struct{}{}
	}
	ids := make([]uint64, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func parseAssetSetID(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(raw), "asa:") {
		raw = strings.TrimSpace(raw[4:])
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid ASA ID %q", raw)
	}
	if id == 0 {
		return 0, fmt.Errorf("0 is not a valid ASA ID")
	}
	return id, nil
}

func joinUint64s(values []uint64) string {
	if len(values) == 0 {
		return ""
	}
	sorted := append([]uint64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	parts := make([]string, 0, len(sorted))
	for _, value := range sorted {
		parts = append(parts, strconv.FormatUint(value, 10))
	}
	return strings.Join(parts, ",")
}
