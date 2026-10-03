// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Config is the effective signer-side policy for one identity.
//
// KeyOverrides maps a concrete signing authority key to a fully resolved Config
// that should be used when that key signs. Signing account overrides are keyed
// by Algorand auth address. Cosigner component overrides are keyed by component
// selector. Overrides inherit from the base config for any field they do not
// set. Nested overrides are not supported (KeyOverrides on an override value is
// always nil).
type Config struct {
	RejectForeignRekey          bool
	RejectRekey                 bool
	RejectCloseRemainder        bool
	RejectAssetClose            bool
	RejectClawback              bool
	AlwaysReviewWarnings        bool
	AutoApproveSelfNoOpTransfer bool
	MaxFeeMicroAlgos            uint64
	ReviewAlgoPayments          map[string]uint64
	MaxAlgoPayments             map[string]uint64
	ReviewASAAmounts            map[string]map[uint64]uint64
	MaxASAAmounts               map[string]map[uint64]uint64
	TransferPolicy              *TransferPolicy
	RekeyPolicy                 *RekeyPolicy
	KeyOverrides                map[string]*Config
	GenesisHashResolver         apconfig.GenesisHashNetworkResolver
	FormatASAAmount             func(network string, assetID uint64, raw uint64) (string, bool)
}

// DefaultConfig returns the default effective policy for new identities.
func DefaultConfig() *Config {
	return DefaultConfigWithGenesisHashResolver(apconfig.DefaultGenesisHashNetworkResolver())
}

// DefaultConfigWithGenesisHashResolver returns the default effective policy
// using the provided genesis-hash-to-network resolver.
func DefaultConfigWithGenesisHashResolver(resolver apconfig.GenesisHashNetworkResolver) *Config {
	return &Config{
		RejectForeignRekey:   true,
		RejectCloseRemainder: false,
		RejectAssetClose:     false,
		RejectClawback:       false,
		ReviewAlgoPayments:   make(map[string]uint64),
		MaxAlgoPayments:      make(map[string]uint64),
		ReviewASAAmounts:     make(map[string]map[uint64]uint64),
		MaxASAAmounts:        make(map[string]map[uint64]uint64),
		GenesisHashResolver:  resolver,
	}
}

// Clone returns a deep copy of the policy config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	cp := *c
	if c.MaxASAAmounts != nil {
		cp.MaxASAAmounts = cloneASAAmounts(c.MaxASAAmounts)
	}
	if c.ReviewASAAmounts != nil {
		cp.ReviewASAAmounts = cloneASAAmounts(c.ReviewASAAmounts)
	}
	if c.MaxAlgoPayments != nil {
		cp.MaxAlgoPayments = cloneUintMap(c.MaxAlgoPayments)
	}
	if c.ReviewAlgoPayments != nil {
		cp.ReviewAlgoPayments = cloneUintMap(c.ReviewAlgoPayments)
	}
	if c.KeyOverrides != nil {
		cp.KeyOverrides = make(map[string]*Config, len(c.KeyOverrides))
		for key, override := range c.KeyOverrides {
			cp.KeyOverrides[key] = override.Clone()
		}
	}
	if c.TransferPolicy != nil {
		cp.TransferPolicy = c.TransferPolicy.Clone()
	}
	if c.RekeyPolicy != nil {
		cp.RekeyPolicy = c.RekeyPolicy.Clone()
	}
	return &cp
}

// ForKey returns the effective config for the given concrete signing authority
// key. If no override is defined for the key, the base config is returned.
func (c *Config) ForKey(key string) *Config {
	if c == nil || key == "" {
		return c
	}
	lookupKey := strings.TrimSpace(key)
	if canonical, err := NormalizeKeyOverrideKey(lookupKey); err == nil {
		lookupKey = canonical
	}
	if override, ok := c.KeyOverrides[lookupKey]; ok {
		return override
	}
	return c
}

// NormalizeKeyOverrideKey canonicalizes a runtime key-override lookup selector.
// It accepts both signer auth addresses and Witness Key IDs because Config.ForKey
// is shared by signer and cosigner effective policy snapshots. Policy document
// validation must use the role-specific normalizers below instead.
func NormalizeKeyOverrideKey(key string) (string, error) {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return "", fmt.Errorf("key override selector is required")
	}
	if selector, err := witness.NormalizeID(raw); err == nil {
		return selector, nil
	}
	if len(raw) == witness.IDLength {
		return "", fmt.Errorf("invalid Witness Key ID %q", raw)
	}
	addr, err := types.DecodeAddress(strings.ToUpper(raw))
	if err != nil {
		return "", fmt.Errorf("key override selector must be an Algorand address or Witness Key ID")
	}
	return addr.String(), nil
}

func cloneUintMap(in map[string]uint64) map[string]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneASAAmounts(in map[string]map[uint64]uint64) map[string]map[uint64]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]map[uint64]uint64, len(in))
	for network, limits := range in {
		if limits == nil {
			out[network] = nil
			continue
		}
		copied := make(map[uint64]uint64, len(limits))
		for assetID, amount := range limits {
			copied[assetID] = amount
		}
		out[network] = copied
	}
	return out
}

func defaultCosignerConfig(defaults *Config) *Config {
	base := DefaultConfig()
	if defaults != nil {
		base = DefaultConfigWithGenesisHashResolver(defaults.GenesisHashResolver)
		base.FormatASAAmount = defaults.FormatASAAmount
	}
	base.RejectForeignRekey = false
	base.RejectRekey = false
	return base
}
