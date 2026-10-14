// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Compile builds the effective policy for the document's key. defaults
// supplies runtime context such as the genesis-hash resolver and the amount
// formatter; nil uses DefaultConfig. Every verdict field comes from the
// document: nothing is inherited from defaults or from any other document.
func (d *PolicyV1) Compile(defaults *Config) (*Config, error) {
	cfg := DefaultConfig()
	if defaults != nil {
		cfg = defaults.Clone()
	}
	cfg.Role = d.Role
	cfg.RejectForeignRekey = d.RejectForeignRekey
	cfg.RejectRekey = d.RejectRekey
	cfg.RejectCloseRemainder = d.RejectCloseRemainder
	cfg.RejectAssetClose = d.RejectAssetClose
	cfg.RejectClawback = d.RejectClawback
	cfg.AlwaysReviewWarnings = d.AlwaysReviewWarnings
	cfg.AutoApproveSelfNoOpTransfer = d.AutoApproveSelfNoOpTransfer
	cfg.MaxFeeMicroAlgos = d.MaxFeeMicroAlgos
	cfg.TransactionTypes = d.TransactionTypes.Clone()
	cfg.RekeyPolicy = nil
	setConfigLimitsV1(cfg, d.Limits)
	addressSets, assetSets, err := compileSetsV1(d.AddressSets, d.AssetSets)
	if err != nil {
		return nil, err
	}
	if cfg.TransferPolicy, err = compileTransferPolicyV1(d.OnNoRoute, d.CloseOnNoRoute, d.ClawbackOnNoRoute,
		d.BlockedDestinations, d.Routes, addressSets, assetSets); err != nil {
		return nil, err
	}
	if len(d.RekeyPolicy) > 0 {
		if cfg.RekeyPolicy, err = compileRekeyPolicyV1(d.RekeyPolicy, addressSets); err != nil {
			return nil, fmt.Errorf("rekey_policy: %w", err)
		}
	}
	if err := ValidateTransferGuards(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// setConfigLimitsV1 replaces the config's amount guards with limits.
func setConfigLimitsV1(cfg *Config, limits LimitsV1) {
	cfg.ReviewAlgoPayments = make(map[string]uint64)
	cfg.MaxAlgoPayments = make(map[string]uint64)
	cfg.ReviewASAAmounts = make(map[string]map[uint64]uint64)
	cfg.MaxASAAmounts = make(map[string]map[uint64]uint64)
	for network, assets := range limits {
		for asset, t := range assets {
			if asset.Algo {
				if t.ReviewAbove != nil {
					cfg.ReviewAlgoPayments[network] = *t.ReviewAbove
				}
				if t.RejectAbove != nil {
					cfg.MaxAlgoPayments[network] = *t.RejectAbove
				}
				continue
			}
			if t.ReviewAbove != nil {
				setNestedLimit(cfg.ReviewASAAmounts, network, asset.ASAID, *t.ReviewAbove)
			}
			if t.RejectAbove != nil {
				setNestedLimit(cfg.MaxASAAmounts, network, asset.ASAID, *t.RejectAbove)
			}
		}
	}
}

func setNestedLimit(m map[string]map[uint64]uint64, network string, assetID, amount uint64) {
	if m[network] == nil {
		m[network] = make(map[uint64]uint64)
	}
	m[network][assetID] = amount
}

func compileSetsV1(addressSets map[string]AddressSetV1, assetSets map[string]AssetSetV1) (map[string]compiledAddressSet, map[string]compiledAssetSet, error) {
	compiledAddresses := make(map[string]compiledAddressSet, len(addressSets))
	for name, set := range addressSets {
		compiledAddresses[name] = compiledAddressSet{
			Flat:      append([]types.Address(nil), set.Flat...),
			ByNetwork: cloneAddressNetworkMap(set.ByNetwork),
		}
	}
	compiledAssets := make(map[string]compiledAssetSet, len(assetSets))
	for name, set := range assetSets {
		cs := compiledAssetSet{ByNetwork: make(map[string][]uint64, len(set))}
		for network, assets := range set {
			for _, asset := range assets {
				if asset.Algo {
					if cs.AlgoNetworks == nil {
						cs.AlgoNetworks = make(map[string]struct{})
					}
					cs.AlgoNetworks[network] = struct{}{}
					continue
				}
				cs.ByNetwork[network] = append(cs.ByNetwork[network], asset.ASAID)
			}
		}
		compiledAssets[name] = cs
	}
	return compiledAddresses, compiledAssets, nil
}

// compileTransferPolicyV1 compiles routes and attaches per-asset limits.
// Decoding has already enforced every rule, so compile errors indicate an
// internal bug.
func compileTransferPolicyV1(
	onNoRoute, closeOnNoRoute, clawbackOnNoRoute TransferOnNoRoute,
	blocked []types.Address,
	routes []RouteV1,
	addressSets map[string]compiledAddressSet,
	assetSets map[string]compiledAssetSet,
) (*TransferPolicy, error) {
	tp := &TransferPolicy{
		OnNoRoute:         onNoRoute,
		CloseOnNoRoute:    closeOnNoRoute,
		ClawbackOnNoRoute: clawbackOnNoRoute,
		AddressSets:       addressSets,
		AssetSets:         assetSets,
		Routes:            make([]CompiledTransferRoute, 0, len(routes)),
	}
	if len(blocked) > 0 {
		tp.BlockedDestinations = make(map[types.Address]struct{}, len(blocked))
		for _, addr := range blocked {
			tp.BlockedDestinations[addr] = struct{}{}
		}
	}
	for _, route := range routes {
		compiled, err := compileRouteV1(route, addressSets, assetSets)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", route.ID, err)
		}
		tp.Routes = append(tp.Routes, compiled)
	}
	return tp, nil
}

// compileRouteV1 compiles one decoded route. Decoding has already enforced
// every route rule, so errors here indicate an internal bug.
func compileRouteV1(route RouteV1, addressSets map[string]compiledAddressSet, assetSets map[string]compiledAssetSet) (CompiledTransferRoute, error) {
	networks := route.Networks
	if route.NetworkWildcard {
		networks = []string{"*"}
	}
	wildcard, networkSet, err := compileNetworks(networks)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	sources, err := compileAddressTerms("sources", route.Sources, addressSets, false)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	assetSources, err := compileAddressTerms("asset_sources", route.AssetSources, addressSets, false)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	assets, err := compileAssetTerms(route.Assets, assetSets)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	destinations, err := compileAddressTerms("destinations", route.Destinations, addressSets, true)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	limits := make(map[string]map[TransferAssetRef]AmountLimits, len(route.Limits))
	for network, byAsset := range route.Limits {
		limits[network] = make(map[TransferAssetRef]AmountLimits, len(byAsset))
		for asset, t := range byAsset {
			limits[network][asset] = AmountLimits{ReviewAbove: cloneUint64Ptr(t.ReviewAbove), RejectAbove: cloneUint64Ptr(t.RejectAbove)}
		}
	}
	return CompiledTransferRoute{
		ID:              route.ID,
		Description:     route.Description,
		NetworkWildcard: wildcard,
		Networks:        networkSet,
		Sources:         sources,
		AssetSources:    assetSources,
		Assets:          assets,
		Destinations:    destinations,
		Limits:          limits,
		AllowClose:      route.AllowClose,
		AllowClawback:   route.AllowClawback,
	}, nil
}

// compileRekeyPolicyV1 compiles decoded rekey rules.
func compileRekeyPolicyV1(rules []RekeyRuleV1, addressSets map[string]compiledAddressSet) (*RekeyPolicy, error) {
	out := &RekeyPolicy{Allowed: make([]CompiledRekeyRule, 0, len(rules))}
	for i, rule := range rules {
		sender, err := compileRekeyAddressTerms(fmt.Sprintf("allowed[%d].sender", i), []string{rule.Sender}, addressSets)
		if err != nil {
			return nil, err
		}
		targets, err := compileRekeyAddressTerms(fmt.Sprintf("allowed[%d].targets", i), rule.Targets, addressSets)
		if err != nil {
			return nil, err
		}
		out.Allowed = append(out.Allowed, CompiledRekeyRule{Sender: sender, Targets: targets})
	}
	return out, nil
}
