// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	TransferOnNoRouteReject          TransferOnNoRoute = "reject"
	TransferOnNoRouteReview          TransferOnNoRoute = "review"
	TransferOnNoRouteOperatorDefault TransferOnNoRoute = "operator_default"
)

// TransferOnNoRoute controls routing's verdict for an in-scope movement that
// matches no route.
type TransferOnNoRoute string

// TransferPolicy is the compiled effective routing policy attached to a policy
// Config.
type TransferPolicy struct {
	Enabled             bool
	OnNoRoute           TransferOnNoRoute
	CloseOnNoRoute      TransferOnNoRoute
	ClawbackOnNoRoute   TransferOnNoRoute
	BlockedDestinations map[types.Address]struct{}
	AddressSets         map[string]compiledAddressSet
	AssetSets           map[string]compiledAssetSet
	Routes              []CompiledTransferRoute
}

// CompiledTransferRoute is one compiled allow-list route.
type CompiledTransferRoute struct {
	ID              string
	Description     string
	NetworkWildcard bool
	Networks        map[string]struct{}
	Sources         compiledAddressTerms
	AssetSources    compiledAddressTerms
	Assets          compiledAssetTerms
	Destinations    compiledAddressTerms
	// Limits holds the route's thresholds keyed by network and asset.
	Limits        map[string]map[TransferAssetRef]AmountLimits
	AllowClose    bool
	AllowClawback bool
}

type AmountLimits struct {
	ReviewAbove *uint64
	RejectAbove *uint64
}

type compiledAddressSet struct {
	Flat      []types.Address
	ByNetwork map[string][]types.Address
}

type compiledAssetSet struct {
	ByNetwork map[string][]uint64
	// AlgoNetworks lists networks on which the set includes ALGO.
	AlgoNetworks map[string]struct{}
}

type compiledAddressTerms struct {
	Wildcard bool
	Self     bool
	Direct   []types.Address
	Sets     []string
}

type compiledAssetTerms struct {
	Wildcard bool
	Algo     bool
	ASAIDs   []uint64
	Sets     []string
}

func (tp *TransferPolicy) Clone() *TransferPolicy {
	if tp == nil {
		return nil
	}
	cp := *tp
	cp.BlockedDestinations = cloneAddressSetMap(tp.BlockedDestinations)
	cp.AddressSets = cloneCompiledAddressSets(tp.AddressSets)
	cp.AssetSets = cloneCompiledAssetSets(tp.AssetSets)
	cp.Routes = cloneCompiledRoutes(tp.Routes)
	return &cp
}

func compileNetworks(raw []string) (bool, map[string]struct{}, error) {
	if len(raw) == 0 {
		return false, nil, fmt.Errorf("networks is required")
	}
	if len(raw) == 1 && raw[0] == "*" {
		return true, nil, nil
	}
	networks := make(map[string]struct{}, len(raw))
	for _, network := range raw {
		if network == "*" {
			return false, nil, fmt.Errorf("networks must be [\"*\"] or concrete tokens, not mixed")
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return false, nil, err
		}
		networks[network] = struct{}{}
	}
	return false, networks, nil
}

func compileAddressTerms(label string, raw []string, sets map[string]compiledAddressSet, allowSelf bool) (compiledAddressTerms, error) {
	if len(raw) == 0 && label != "asset_sources" {
		return compiledAddressTerms{}, fmt.Errorf("%s is required", label)
	}
	var out compiledAddressTerms
	for _, term := range raw {
		switch {
		case term == "*":
			out.Wildcard = true
		case term == "self":
			if !allowSelf {
				return compiledAddressTerms{}, fmt.Errorf("self is not allowed in %s", label)
			}
			out.Self = true
		case strings.HasPrefix(term, "@"):
			name := strings.TrimPrefix(term, "@")
			if _, ok := sets[name]; !ok {
				return compiledAddressTerms{}, fmt.Errorf("unresolved address set %q in %s", name, label)
			}
			out.Sets = append(out.Sets, name)
		default:
			addr, err := types.DecodeAddress(term)
			if err != nil {
				return compiledAddressTerms{}, fmt.Errorf("invalid address %q in %s: %w", term, label, err)
			}
			out.Direct = append(out.Direct, addr)
		}
	}
	return out, nil
}

// compileAssetTerms compiles v1 asset terms: "*", "algo", "@set", or
// "asa:<id>".
func compileAssetTerms(raw []string, sets map[string]compiledAssetSet) (compiledAssetTerms, error) {
	if len(raw) == 0 {
		return compiledAssetTerms{}, fmt.Errorf("assets is required")
	}
	var out compiledAssetTerms
	for _, term := range raw {
		switch {
		case term == "*":
			out.Wildcard = true
		case strings.HasPrefix(term, "@"):
			name := strings.TrimPrefix(term, "@")
			if _, ok := sets[name]; !ok {
				return compiledAssetTerms{}, fmt.Errorf("unresolved asset set %q", name)
			}
			out.Sets = append(out.Sets, name)
		default:
			ref, err := parseAssetRefV1("", term)
			if err != nil {
				return compiledAssetTerms{}, err
			}
			if ref.Algo {
				out.Algo = true
			} else {
				out.ASAIDs = append(out.ASAIDs, ref.ASAID)
			}
		}
	}
	return out, nil
}

func cloneUint64Ptr(v *uint64) *uint64 {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func cloneAddressSetMap(in map[types.Address]struct{}) map[types.Address]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[types.Address]struct{}, len(in))
	for addr := range in {
		out[addr] = struct{}{}
	}
	return out
}

func cloneCompiledAddressSets(in map[string]compiledAddressSet) map[string]compiledAddressSet {
	if in == nil {
		return nil
	}
	out := make(map[string]compiledAddressSet, len(in))
	for name, set := range in {
		out[name] = compiledAddressSet{
			Flat:      append([]types.Address(nil), set.Flat...),
			ByNetwork: cloneAddressNetworkMap(set.ByNetwork),
		}
	}
	return out
}

func cloneCompiledAssetSets(in map[string]compiledAssetSet) map[string]compiledAssetSet {
	if in == nil {
		return nil
	}
	out := make(map[string]compiledAssetSet, len(in))
	for name, set := range in {
		out[name] = compiledAssetSet{ByNetwork: cloneUintNetworkMap(set.ByNetwork), AlgoNetworks: cloneStringSet(set.AlgoNetworks)}
	}
	return out
}

func cloneCompiledRoutes(in []CompiledTransferRoute) []CompiledTransferRoute {
	if in == nil {
		return nil
	}
	out := make([]CompiledTransferRoute, len(in))
	for i, route := range in {
		out[i] = route
		out[i].Networks = cloneStringSet(route.Networks)
		out[i].Sources = cloneAddressTerms(route.Sources)
		out[i].AssetSources = cloneAddressTerms(route.AssetSources)
		out[i].Assets = cloneAssetTerms(route.Assets)
		out[i].Destinations = cloneAddressTerms(route.Destinations)
		out[i].Limits = cloneRouteLimits(route.Limits)
	}
	return out
}

func cloneRouteLimits(in map[string]map[TransferAssetRef]AmountLimits) map[string]map[TransferAssetRef]AmountLimits {
	if in == nil {
		return nil
	}
	out := make(map[string]map[TransferAssetRef]AmountLimits, len(in))
	for network, assets := range in {
		out[network] = make(map[TransferAssetRef]AmountLimits, len(assets))
		for asset, limits := range assets {
			out[network][asset] = AmountLimits{
				ReviewAbove: cloneUint64Ptr(limits.ReviewAbove),
				RejectAbove: cloneUint64Ptr(limits.RejectAbove),
			}
		}
	}
	return out
}

func cloneAddressTerms(in compiledAddressTerms) compiledAddressTerms {
	return compiledAddressTerms{
		Wildcard: in.Wildcard,
		Self:     in.Self,
		Direct:   append([]types.Address(nil), in.Direct...),
		Sets:     append([]string(nil), in.Sets...),
	}
}

func cloneAssetTerms(in compiledAssetTerms) compiledAssetTerms {
	return compiledAssetTerms{
		Wildcard: in.Wildcard,
		Algo:     in.Algo,
		ASAIDs:   append([]uint64(nil), in.ASAIDs...),
		Sets:     append([]string(nil), in.Sets...),
	}
}

func cloneAddressNetworkMap(in map[string][]types.Address) map[string][]types.Address {
	if in == nil {
		return nil
	}
	out := make(map[string][]types.Address, len(in))
	for network, addresses := range in {
		out[network] = append([]types.Address(nil), addresses...)
	}
	return out
}

func cloneUintNetworkMap(in map[string][]uint64) map[string][]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string][]uint64, len(in))
	for network, values := range in {
		out[network] = append([]uint64(nil), values...)
	}
	return out
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for v := range in {
		out[v] = struct{}{}
	}
	return out
}
