// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Compile builds the effective signer policy. defaults supplies runtime
// context such as the genesis-hash resolver; nil uses DefaultConfig. Key
// overrides resolve against the compiled document, never against each other.
func (d *SignerPolicyV1) Compile(defaults *Config) (*Config, error) {
	cfg := DefaultConfig()
	if defaults != nil {
		cfg = defaults.Clone()
	}
	cfg.KeyOverrides = nil
	applySignerSettingsV1(cfg, d.SignerSettingsV1)
	setConfigLimitsV1(cfg, d.Limits)
	addressSets, assetSets, err := compileSetsV1(d.AddressSets, d.AssetSets)
	if err != nil {
		return nil, err
	}
	if tp := d.TransferPolicy; tp != nil {
		closeMiss, clawbackMiss := tp.CloseOnNoRoute, tp.ClawbackOnNoRoute
		if closeMiss == "" {
			closeMiss = TransferOnNoRouteReject
		}
		if clawbackMiss == "" {
			clawbackMiss = TransferOnNoRouteReject
		}
		if cfg.TransferPolicy, err = compileTransferPolicyV1(tp.Enabled, tp.OnNoRoute, closeMiss, clawbackMiss,
			tp.BlockedDestinations, tp.Routes, addressSets, assetSets); err != nil {
			return nil, err
		}
	}
	if err := ValidateTransferGuards(cfg); err != nil {
		return nil, err
	}

	if len(d.KeyOverrides) > 0 {
		cfg.KeyOverrides = make(map[string]*Config, len(d.KeyOverrides))
		for _, key := range sortedKeys(d.KeyOverrides) {
			ov := d.KeyOverrides[key]
			overrideCfg := cfg.Clone()
			overrideCfg.KeyOverrides = nil
			applySignerSettingsV1(overrideCfg, ov.SignerSettingsV1)
			setConfigLimitsV1(overrideCfg, mergeOverrideLimits(d.Limits, ov.Limits))
			if err := ValidateTransferGuards(overrideCfg); err != nil {
				return nil, fmt.Errorf("key_overrides for %q: %w", key, err)
			}
			cfg.KeyOverrides[key] = overrideCfg
		}
	}
	return cfg, nil
}

// Compile builds the effective policy for the document's cosigner key. Route
// misses, close-outs, and clawbacks without a route are always rejected.
func (d *CosignerPolicyV1) Compile(defaults *Config) (*Config, error) {
	cfg := defaultCosignerConfig(defaults)
	cfg.KeyOverrides = nil
	for _, f := range []struct {
		src *bool
		dst *bool
	}{
		{d.RejectCloseRemainder, &cfg.RejectCloseRemainder},
		{d.RejectAssetClose, &cfg.RejectAssetClose},
		{d.RejectClawback, &cfg.RejectClawback},
		{d.RejectRekey, &cfg.RejectRekey},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if d.MaxFeeMicroAlgos != nil {
		cfg.MaxFeeMicroAlgos = *d.MaxFeeMicroAlgos
	}
	setConfigLimitsV1(cfg, d.Limits)
	addressSets, assetSets, err := compileSetsV1(d.AddressSets, d.AssetSets)
	if err != nil {
		return nil, err
	}
	if cfg.TransferPolicy, err = compileTransferPolicyV1(true, TransferOnNoRouteReject, TransferOnNoRouteReject,
		TransferOnNoRouteReject, d.BlockedDestinations, d.Routes, addressSets, assetSets); err != nil {
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

func applySignerSettingsV1(cfg *Config, s SignerSettingsV1) {
	for _, f := range []struct {
		src *bool
		dst *bool
	}{
		{s.RejectForeignRekey, &cfg.RejectForeignRekey},
		{s.RejectCloseRemainder, &cfg.RejectCloseRemainder},
		{s.RejectAssetClose, &cfg.RejectAssetClose},
		{s.RejectClawback, &cfg.RejectClawback},
		{s.AlwaysReviewWarnings, &cfg.AlwaysReviewWarnings},
		{s.AutoApproveSelfNoOpTransfer, &cfg.AutoApproveSelfNoOpTransfer},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if s.MaxFeeMicroAlgos != nil {
		cfg.MaxFeeMicroAlgos = *s.MaxFeeMicroAlgos
	}
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

// compileTransferPolicyV1 compiles routes through the same term and rule
// compiler as policy.yaml, then attaches per-asset limits. Decoding has
// already enforced every rule, so compile errors indicate an internal bug.
func compileTransferPolicyV1(
	enabled bool,
	onNoRoute, closeOnNoRoute, clawbackOnNoRoute TransferOnNoRoute,
	blocked []types.Address,
	routes []RouteV1,
	addressSets map[string]compiledAddressSet,
	assetSets map[string]compiledAssetSet,
) (*TransferPolicy, error) {
	tp := &TransferPolicy{
		Enabled:           enabled,
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
