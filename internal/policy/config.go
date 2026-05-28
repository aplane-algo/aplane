// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"gopkg.in/yaml.v3"
)

// Config is the effective signer-side policy for one identity.
//
// KeyTypeOverrides maps key type (e.g. "aplane.falcon1024-whitelist.v1") to a fully
// resolved Config that should be used when a transaction is signed by a key
// of that type. Overrides inherit from the base config for any field they do
// not set. Nested overrides are not supported (KeyTypeOverrides on an override
// value is always nil).
type Config struct {
	RejectForeignRekey          bool
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
	KeyTypeOverrides            map[string]*Config
	GenesisHashResolver         apconfig.GenesisHashNetworkResolver
	FormatASAAmount             func(network string, assetID uint64, raw uint64) (string, bool)
}

// StoredConfig is the persisted YAML representation for identity-scoped policy.
// Nil booleans mean "use default". Zero threshold values mean "no limit".
// KeyTypeOverrides is a map from key type to a sparse StoredConfig that is
// layered on top of the identity-wide settings when the signing key has that
// type. Overrides never recurse.
type StoredConfig struct {
	RejectForeignRekey          *bool                        `yaml:"reject_foreign_rekey,omitempty"`
	RejectCloseRemainder        *bool                        `yaml:"reject_close_remainder,omitempty"`
	RejectAssetClose            *bool                        `yaml:"reject_asset_close,omitempty"`
	RejectClawback              *bool                        `yaml:"reject_clawback,omitempty"`
	AlwaysReviewWarnings        *bool                        `yaml:"always_review_warnings,omitempty"`
	AutoApproveSelfNoOpTransfer *bool                        `yaml:"auto_approve_self_noop_transfer,omitempty"`
	MaxFeeMicroAlgos            *uint64                      `yaml:"max_fee_microalgos,omitempty"`
	ReviewAlgoPayments          map[string]uint64            `yaml:"review_algo_payments,omitempty"`
	MaxAlgoPayments             map[string]uint64            `yaml:"max_algo_payments,omitempty"`
	ReviewASAAmounts            map[string]map[string]uint64 `yaml:"review_asa_amounts,omitempty"`
	MaxASAAmounts               map[string]map[string]uint64 `yaml:"max_asa_amounts,omitempty"`
	TransferPolicy              *StoredTransferPolicy        `yaml:"transfer_policy,omitempty"`
	KeyTypeOverrides            map[string]*StoredConfig     `yaml:"key_type_overrides,omitempty"`
}

// Clone returns a deep copy of the stored policy config.
func (c *StoredConfig) Clone() *StoredConfig {
	if c == nil {
		return nil
	}
	cp := *c
	cp.RejectForeignRekey = cloneBoolPtr(c.RejectForeignRekey)
	cp.RejectCloseRemainder = cloneBoolPtr(c.RejectCloseRemainder)
	cp.RejectAssetClose = cloneBoolPtr(c.RejectAssetClose)
	cp.RejectClawback = cloneBoolPtr(c.RejectClawback)
	cp.AlwaysReviewWarnings = cloneBoolPtr(c.AlwaysReviewWarnings)
	cp.AutoApproveSelfNoOpTransfer = cloneBoolPtr(c.AutoApproveSelfNoOpTransfer)
	cp.MaxFeeMicroAlgos = cloneUint64Ptr(c.MaxFeeMicroAlgos)
	cp.ReviewAlgoPayments = cloneUintMap(c.ReviewAlgoPayments)
	cp.MaxAlgoPayments = cloneUintMap(c.MaxAlgoPayments)
	cp.ReviewASAAmounts = cloneStoredASAAmounts(c.ReviewASAAmounts)
	cp.MaxASAAmounts = cloneStoredASAAmounts(c.MaxASAAmounts)
	cp.TransferPolicy = c.TransferPolicy.Clone()
	if c.KeyTypeOverrides != nil {
		cp.KeyTypeOverrides = make(map[string]*StoredConfig, len(c.KeyTypeOverrides))
		for keyType, override := range c.KeyTypeOverrides {
			cp.KeyTypeOverrides[keyType] = override.Clone()
		}
	}
	return &cp
}

func (c *StoredConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("policy config must be a mapping")
	}
	allowed := map[string]struct{}{
		"reject_foreign_rekey":            {},
		"reject_close_remainder":          {},
		"reject_asset_close":              {},
		"reject_clawback":                 {},
		"always_review_warnings":          {},
		"auto_approve_self_noop_transfer": {},
		"max_fee_microalgos":              {},
		"review_algo_payments":            {},
		"max_algo_payments":               {},
		"review_asa_amounts":              {},
		"max_asa_amounts":                 {},
		"transfer_policy":                 {},
		"key_type_overrides":              {},
	}
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown policy field %q", key)
		}
	}
	type rawConfig struct {
		RejectForeignRekey          *bool                        `yaml:"reject_foreign_rekey,omitempty"`
		RejectCloseRemainder        *bool                        `yaml:"reject_close_remainder,omitempty"`
		RejectAssetClose            *bool                        `yaml:"reject_asset_close,omitempty"`
		RejectClawback              *bool                        `yaml:"reject_clawback,omitempty"`
		AlwaysReviewWarnings        *bool                        `yaml:"always_review_warnings,omitempty"`
		AutoApproveSelfNoOpTransfer *bool                        `yaml:"auto_approve_self_noop_transfer,omitempty"`
		MaxFeeMicroAlgos            *uint64                      `yaml:"max_fee_microalgos,omitempty"`
		ReviewAlgoPayments          map[string]uint64            `yaml:"review_algo_payments,omitempty"`
		MaxAlgoPayments             map[string]uint64            `yaml:"max_algo_payments,omitempty"`
		ReviewASAAmounts            map[string]map[string]uint64 `yaml:"review_asa_amounts,omitempty"`
		MaxASAAmounts               map[string]map[string]uint64 `yaml:"max_asa_amounts,omitempty"`
		TransferPolicy              *StoredTransferPolicy        `yaml:"transfer_policy,omitempty"`
		KeyTypeOverrides            map[string]*StoredConfig     `yaml:"key_type_overrides,omitempty"`
	}
	var raw rawConfig
	if err := value.Decode(&raw); err != nil {
		return err
	}
	c.RejectForeignRekey = raw.RejectForeignRekey
	c.RejectCloseRemainder = raw.RejectCloseRemainder
	c.RejectAssetClose = raw.RejectAssetClose
	c.RejectClawback = raw.RejectClawback
	c.AlwaysReviewWarnings = raw.AlwaysReviewWarnings
	c.AutoApproveSelfNoOpTransfer = raw.AutoApproveSelfNoOpTransfer
	c.MaxFeeMicroAlgos = raw.MaxFeeMicroAlgos
	c.ReviewAlgoPayments = raw.ReviewAlgoPayments
	c.MaxAlgoPayments = raw.MaxAlgoPayments
	c.ReviewASAAmounts = raw.ReviewASAAmounts
	c.MaxASAAmounts = raw.MaxASAAmounts
	c.TransferPolicy = raw.TransferPolicy
	c.KeyTypeOverrides = raw.KeyTypeOverrides
	return nil
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
	if c.KeyTypeOverrides != nil {
		cp.KeyTypeOverrides = make(map[string]*Config, len(c.KeyTypeOverrides))
		for kt, override := range c.KeyTypeOverrides {
			cp.KeyTypeOverrides[kt] = override.Clone()
		}
	}
	if c.TransferPolicy != nil {
		cp.TransferPolicy = c.TransferPolicy.Clone()
	}
	return &cp
}

// ForKeyType returns the effective config for the given key type. If no
// override is defined for the key type, the base config is returned.
func (c *Config) ForKeyType(keyType string) *Config {
	if c == nil || keyType == "" {
		return c
	}
	if override, ok := c.KeyTypeOverrides[keyType]; ok {
		return override
	}
	return c
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

func cloneValidatedNetworkUintMap(label string, in map[string]uint64) (map[string]uint64, error) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]uint64, len(in))
	for network, amount := range in {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid %s network %q: %w", label, network, err)
		}
		out[network] = amount
	}
	return out, nil
}

func compileStoredASAAmounts(label string, in map[string]map[string]uint64) (map[string]map[uint64]uint64, error) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]map[uint64]uint64, len(in))
	for network, limits := range in {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid %s network %q: %w", label, network, err)
		}
		if limits == nil {
			out[network] = nil
			continue
		}
		compiled := make(map[uint64]uint64, len(limits))
		for rawID, amount := range limits {
			assetID, err := parseStoredASAID(label, network, rawID)
			if err != nil {
				return nil, err
			}
			if _, ok := compiled[assetID]; ok {
				return nil, fmt.Errorf("%s[%s]: duplicate ASA ID %d", label, network, assetID)
			}
			compiled[assetID] = amount
		}
		out[network] = compiled
	}
	return out, nil
}

func parseStoredASAID(label, network, rawID string) (uint64, error) {
	assetID, err := strconv.ParseUint(rawID, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s key %q for network %q: %w", label, rawID, network, err)
	}
	if assetID == 0 {
		return 0, fmt.Errorf("invalid %s key %q for network %q: 0 is not a valid ASA ID", label, rawID, network)
	}
	if strconv.FormatUint(assetID, 10) != rawID {
		return 0, fmt.Errorf("invalid %s key %q for network %q: ASA IDs must be canonical unsigned decimal", label, rawID, network)
	}
	return assetID, nil
}

func cloneStoredASAAmounts(in map[string]map[string]uint64) map[string]map[string]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]map[string]uint64, len(in))
	for network, limits := range in {
		if limits == nil {
			out[network] = nil
			continue
		}
		copied := make(map[string]uint64, len(limits))
		for assetID, amount := range limits {
			copied[assetID] = amount
		}
		out[network] = copied
	}
	return out
}

func cloneBoolPtr(in *bool) *bool {
	if in == nil {
		return nil
	}
	v := *in
	return &v
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

// PolicyPath returns the path to an identity policy file.
func PolicyPath(dataRoot, identityID string) string {
	return filepath.Join(dataRoot, "identities", identityID, "policy.yaml")
}

// LoadStoredConfig reads the per-identity policy file. Missing files return an empty config.
func LoadStoredConfig(dataRoot, identityID string) (*StoredConfig, error) {
	path := PolicyPath(dataRoot, identityID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &StoredConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read policy config: %w", err)
	}

	cfg, err := ParseStoredConfig(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy config: %w", err)
	}
	return cfg, nil
}

// SaveStoredConfig writes a whole identity policy file atomically.
func SaveStoredConfig(dataRoot, identityID string, cfg *StoredConfig) error {
	path := PolicyPath(dataRoot, identityID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create policy directory: %w", err)
	}

	out, err := MarshalStoredConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("failed to write policy config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to rename policy config: %w", err)
	}
	return nil
}

// ParseStoredConfig parses policy YAML bytes without performing any integrity
// verification. Callers that need authoritative signer policy should use
// LoadVerifiedStoredConfig once policy integrity is enforced.
func ParseStoredConfig(data []byte) (*StoredConfig, error) {
	var cfg StoredConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// MarshalStoredConfig serializes a whole stored policy config.
func MarshalStoredConfig(cfg *StoredConfig) ([]byte, error) {
	if cfg == nil {
		cfg = &StoredConfig{}
	}
	return yaml.Marshal(cfg)
}

// Apply overlays stored values onto defaults and returns the effective policy.
func (c *StoredConfig) Apply(defaults *Config) (*Config, error) {
	effective := DefaultConfig()
	if defaults != nil {
		effective = defaults.Clone()
	}
	if effective.MaxASAAmounts == nil {
		effective.MaxASAAmounts = make(map[string]map[uint64]uint64)
	}
	if effective.ReviewASAAmounts == nil {
		effective.ReviewASAAmounts = make(map[string]map[uint64]uint64)
	}
	if effective.MaxAlgoPayments == nil {
		effective.MaxAlgoPayments = make(map[string]uint64)
	}
	if effective.ReviewAlgoPayments == nil {
		effective.ReviewAlgoPayments = make(map[string]uint64)
	}

	if c == nil {
		if err := ValidateTransferGuards(effective); err != nil {
			return nil, err
		}
		return effective, nil
	}

	if c.RejectForeignRekey != nil {
		effective.RejectForeignRekey = *c.RejectForeignRekey
	}
	if c.RejectCloseRemainder != nil {
		effective.RejectCloseRemainder = *c.RejectCloseRemainder
	}
	if c.RejectAssetClose != nil {
		effective.RejectAssetClose = *c.RejectAssetClose
	}
	if c.RejectClawback != nil {
		effective.RejectClawback = *c.RejectClawback
	}
	if c.AlwaysReviewWarnings != nil {
		effective.AlwaysReviewWarnings = *c.AlwaysReviewWarnings
	}
	if c.AutoApproveSelfNoOpTransfer != nil {
		effective.AutoApproveSelfNoOpTransfer = *c.AutoApproveSelfNoOpTransfer
	}
	if c.MaxFeeMicroAlgos != nil {
		effective.MaxFeeMicroAlgos = *c.MaxFeeMicroAlgos
	}
	if c.ReviewAlgoPayments != nil {
		reviewAlgo, err := cloneValidatedNetworkUintMap("review_algo_payments", c.ReviewAlgoPayments)
		if err != nil {
			return nil, err
		}
		effective.ReviewAlgoPayments = reviewAlgo
	}
	if c.MaxAlgoPayments != nil {
		maxAlgo, err := cloneValidatedNetworkUintMap("max_algo_payments", c.MaxAlgoPayments)
		if err != nil {
			return nil, err
		}
		effective.MaxAlgoPayments = maxAlgo
	}
	if c.ReviewASAAmounts != nil {
		reviewASA, err := compileStoredASAAmounts("review_asa_amounts", c.ReviewASAAmounts)
		if err != nil {
			return nil, err
		}
		effective.ReviewASAAmounts = reviewASA
	}
	if c.MaxASAAmounts != nil {
		maxASA, err := compileStoredASAAmounts("max_asa_amounts", c.MaxASAAmounts)
		if err != nil {
			return nil, err
		}
		effective.MaxASAAmounts = maxASA
	}
	if c.TransferPolicy != nil {
		compiled, err := c.TransferPolicy.Apply(effective.TransferPolicy)
		if err != nil {
			return nil, fmt.Errorf("transfer_policy: %w", err)
		}
		effective.TransferPolicy = compiled
	}

	if len(c.KeyTypeOverrides) > 0 {
		// Use a detached copy of the resolved base as the "defaults" for each
		// override so overrides only see their own fields plus the identity
		// base, never other overrides.
		overrideBase := effective.Clone()
		overrideBase.KeyTypeOverrides = nil
		effective.KeyTypeOverrides = make(map[string]*Config, len(c.KeyTypeOverrides))
		for keyType, overrideStored := range c.KeyTypeOverrides {
			if overrideStored == nil {
				continue
			}
			if len(overrideStored.KeyTypeOverrides) > 0 {
				return nil, fmt.Errorf("key_type_overrides for %q: nested key_type_overrides are not supported", keyType)
			}
			overrideCfg, err := overrideStored.Apply(overrideBase)
			if err != nil {
				return nil, fmt.Errorf("key_type_overrides for %q: %w", keyType, err)
			}
			overrideCfg.KeyTypeOverrides = nil
			effective.KeyTypeOverrides[keyType] = overrideCfg
		}
	}

	if err := ValidateTransferGuards(effective); err != nil {
		return nil, err
	}

	return effective, nil
}
