// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package registry owns APlane's built-in ASA metadata and convenience aliases.
package registry

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Info is static metadata for a built-in ASA.
type Info struct {
	Name     string
	UnitName string
	Decimals uint64
}

var builtinMetadata = map[string]map[uint64]Info{
	"mainnet": {
		// Stablecoins
		31566704:  {Name: "USDC", UnitName: "USDC", Decimals: 6},
		672913181: {Name: "goUSD", UnitName: "goUSD", Decimals: 6},
		760037151: {Name: "xUSD", UnitName: "xUSD", Decimals: 6},
		465865291: {Name: "STBL", UnitName: "STBL", Decimals: 6},
		841126810: {Name: "STBL2", UnitName: "STBL2", Decimals: 6},
		227855942: {Name: "STASIS EURO", UnitName: "EURS", Decimals: 2},

		// Wrapped assets
		386192725:  {Name: "goBTC", UnitName: "goBTC", Decimals: 8},
		386195940:  {Name: "goETH", UnitName: "goETH", Decimals: 8},
		1058926737: {Name: "Wrapped BTC", UnitName: "WBTC", Decimals: 8},
		887406851:  {Name: "Wrapped Ether", UnitName: "WETH", Decimals: 8},
		887648583:  {Name: "Wrapped SOL", UnitName: "SOL", Decimals: 8},
		893309613:  {Name: "Wrapped AVAX", UnitName: "WAVAX", Decimals: 8},
		1200094857: {Name: "ChainLink Token", UnitName: "LINK", Decimals: 8},

		// Liquid staking / governance
		1134696561: {Name: "Governance xAlgo", UnitName: "xALGO", Decimals: 6},
		2537013734: {Name: "tALGO", UnitName: "TALGO", Decimals: 6},
		793124631:  {Name: "Governance Algo", UnitName: "gALGO", Decimals: 6},
		1185173782: {Name: "mALGO", UnitName: "mALGO", Decimals: 6},
		2400334372: {Name: "cAlgo", UnitName: "cAlgo", Decimals: 6},

		// Precious metals (Meld)
		246516580: {Name: "Meld Gold (g)", UnitName: "GOLD$", Decimals: 6},
		246519683: {Name: "Meld Silver (g)", UnitName: "SILVER$", Decimals: 6},

		// Bridge tokens
		2320775407: {Name: "Aramid VOI", UnitName: "aVoi", Decimals: 6},

		// DeFi / Governance tokens
		2200000000: {Name: "TINY", UnitName: "TINY", Decimals: 6},
		3203964481: {Name: "Folks Finance", UnitName: "FOLKS", Decimals: 6},
		1138500612: {Name: "GORA", UnitName: "GORA", Decimals: 9},
		849191641:  {Name: "Hesab Afghani", UnitName: "HAFN", Decimals: 2},
		849229386:  {Name: "Hesab USD", UnitName: "HUSD", Decimals: 2},
		470842789:  {Name: "Defly Token", UnitName: "DEFLY", Decimals: 6},
		700965019:  {Name: "Vestige", UnitName: "VEST", Decimals: 6},
		452399768:  {Name: "Vote Coin", UnitName: "Vote", Decimals: 6},
		796425061:  {Name: "Coop Coin", UnitName: "COOP", Decimals: 6},
		1732165149: {Name: "CompX Token", UnitName: "COMPX", Decimals: 6},
		393537671:  {Name: "ASA Stats Token", UnitName: "ASASTATS", Decimals: 6},

		// Popular community tokens
		2726252423: {Name: "Alpha Arcade", UnitName: "ALPHA", Decimals: 6},
		523683256:  {Name: "AKITA INU", UnitName: "AKTA", Decimals: 0},
	},
	"testnet": {
		10458941: {Name: "USDC", UnitName: "USDC", Decimals: 6},
	},
}

// convenienceAliases are explicit compatibility aliases that do not necessarily
// imply trusted static metadata for the target asset.
var convenienceAliases = map[string]map[string]uint64{
	"mainnet": {
		"akita": 523683256,
		"chips": 388592191,
		"gard":  684649988,
		"ora":   1284444444,
		"pepe":  1096015467,
	},
}

// BuiltinMetadata returns static metadata for a built-in ASA.
func BuiltinMetadata(network string, assetID uint64) (Info, bool) {
	assets, ok := builtinMetadata[normalizeNetwork(network)]
	if !ok {
		return Info{}, false
	}
	info, ok := assets[assetID]
	return info, ok
}

// AllBuiltinMetadata returns a copy of static metadata for a network.
func AllBuiltinMetadata(network string) map[uint64]Info {
	assets, ok := builtinMetadata[normalizeNetwork(network)]
	if !ok {
		return nil
	}
	out := make(map[uint64]Info, len(assets))
	for assetID, info := range assets {
		out[assetID] = info
	}
	return out
}

// IsBuiltinMetadata reports whether static metadata is available for an ASA.
func IsBuiltinMetadata(network string, assetID uint64) bool {
	_, ok := BuiltinMetadata(network, assetID)
	return ok
}

// BuiltinUnitName returns a built-in unit name when static metadata is present.
func BuiltinUnitName(network string, assetID uint64) (string, bool) {
	info, ok := BuiltinMetadata(network, assetID)
	if !ok || strings.TrimSpace(info.UnitName) == "" {
		return "", false
	}
	return info.UnitName, true
}

// ResolveReference resolves a static built-in unit/name or explicit alias.
func ResolveReference(network, ref string) (uint64, bool, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, false, nil
	}
	network = normalizeNetwork(network)
	if assetID, err := strconv.ParseUint(ref, 10, 64); err == nil {
		if IsBuiltinMetadata(network, assetID) || isAliasTarget(network, assetID) {
			return assetID, true, nil
		}
		return 0, false, nil
	}

	key := normalizeRef(ref)
	matches := make(map[uint64]struct{})
	if assets, ok := builtinMetadata[network]; ok {
		for assetID, info := range assets {
			if normalizeRef(info.UnitName) == key || normalizeRef(info.Name) == key {
				matches[assetID] = struct{}{}
			}
		}
	}
	if aliases, ok := convenienceAliases[network]; ok {
		if assetID, ok := aliases[key]; ok {
			matches[assetID] = struct{}{}
		}
	}

	ids := sortedIDs(matches)
	if len(ids) == 0 {
		return 0, false, nil
	}
	if len(ids) > 1 {
		return 0, false, fmt.Errorf("ASA reference %q is ambiguous in %s built-ins; matches asset IDs %s", ref, network, formatAssetIDList(ids))
	}
	return ids[0], true, nil
}

func isAliasTarget(network string, assetID uint64) bool {
	for _, id := range convenienceAliases[network] {
		if id == assetID {
			return true
		}
	}
	return false
}

func normalizeNetwork(network string) string {
	return strings.ToLower(strings.TrimSpace(network))
}

func normalizeRef(ref string) string {
	return strings.ToLower(strings.TrimSpace(ref))
}

func sortedIDs(matches map[uint64]struct{}) []uint64 {
	ids := make([]uint64, 0, len(matches))
	for id := range matches {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func formatAssetIDList(ids []uint64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatUint(id, 10)
	}
	return strings.Join(parts, ", ")
}
