// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
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

// StoredConfig is the persisted YAML representation for signer policy.
// Nil booleans mean "use default". Zero threshold values mean "no limit".
// KeyOverrides is a map from concrete signing authority key to a sparse
// StoredConfig that is layered on top of the product-wide settings when that
// key signs. Overrides never recurse.
type StoredConfig struct {
	StoredPolicyCore `yaml:",inline"`

	KeyOverrides map[string]*StoredConfig `yaml:"key_overrides,omitempty"`
}

// StoredPolicyCore is the policy field block of a document or key override.
// The node role decides which fields are valid: signer documents reject the
// cosigner-only fields and cosigner documents reject the review fields.
type StoredPolicyCore struct {
	RejectRekey                 *bool                        `yaml:"reject_rekey,omitempty"`
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
	RekeyPolicy                 *StoredRekeyPolicy           `yaml:"rekey_policy,omitempty"`
}

// storedPolicyCoreFields lists the YAML keys of StoredPolicyCore for the
// unmarshal allow-lists. It is derived from the struct tags so the allow-lists
// cannot drift from the struct.
var storedPolicyCoreFields = yamlFieldNames(reflect.TypeOf(StoredPolicyCore{}))

func yamlFieldNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		names = append(names, name)
	}
	return names
}

func allowedFieldSet(fields ...string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(storedPolicyCoreFields)+len(fields))
	for _, key := range storedPolicyCoreFields {
		allowed[key] = struct{}{}
	}
	for _, key := range fields {
		allowed[key] = struct{}{}
	}
	return allowed
}

// Clone returns a deep copy of the shared policy field block.
func (c *StoredPolicyCore) Clone() *StoredPolicyCore {
	if c == nil {
		return nil
	}
	cp := *c
	cp.RejectRekey = cloneBoolPtr(c.RejectRekey)
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
	cp.RekeyPolicy = c.RekeyPolicy.Clone()
	return &cp
}

// Clone returns a deep copy of the stored policy config.
func (c *StoredConfig) Clone() *StoredConfig {
	if c == nil {
		return nil
	}
	cp := *c
	cp.StoredPolicyCore = *c.StoredPolicyCore.Clone()
	if c.KeyOverrides != nil {
		cp.KeyOverrides = make(map[string]*StoredConfig, len(c.KeyOverrides))
		for key, override := range c.KeyOverrides {
			cp.KeyOverrides[key] = override.Clone()
		}
	}
	return &cp
}

func (c *StoredConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("policy config must be a mapping")
	}
	allowed := allowedFieldSet("key_overrides")
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if key == "cosigner" {
			return fmt.Errorf("policy must not contain a cosigner wrapper; cosigner policy is a cosigner node's policy.yaml with fields at top level")
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown policy field %q", key)
		}
	}
	type rawConfig StoredConfig
	var raw rawConfig
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*c = StoredConfig(raw)
	return nil
}

// validateCosignerFields rejects the fields cosigner policy cannot honor:
// those that produce review verdicts or assume an operator above the signer.
func validateCosignerFields(cfg *StoredPolicyCore) error {
	if cfg.RejectForeignRekey != nil {
		return fmt.Errorf("cosigner.reject_foreign_rekey is not supported; use cosigner.reject_rekey")
	}
	if cfg.AlwaysReviewWarnings != nil {
		return fmt.Errorf("cosigner.always_review_warnings is not supported; cosigner policy cannot produce review verdicts")
	}
	if cfg.AutoApproveSelfNoOpTransfer != nil {
		return fmt.Errorf("cosigner.auto_approve_self_noop_transfer is not supported; cosigner has no operator default")
	}
	if len(cfg.ReviewAlgoPayments) > 0 {
		return fmt.Errorf("cosigner.review_algo_payments is not supported; cosigner policy cannot produce review verdicts")
	}
	if len(cfg.ReviewASAAmounts) > 0 {
		return fmt.Errorf("cosigner.review_asa_amounts is not supported; cosigner policy cannot produce review verdicts")
	}
	if err := validateCosignerTransferPolicy(cfg.TransferPolicy); err != nil {
		return err
	}
	return nil
}

func validateCosignerTransferPolicy(tp *StoredTransferPolicy) error {
	if tp == nil {
		return nil
	}
	if err := requireRejectRouteMiss("cosigner.transfer_policy.on_no_route", tp.OnNoRoute); err != nil {
		return err
	}
	if err := requireRejectRouteMiss("cosigner.transfer_policy.close_on_no_route", tp.CloseOnNoRoute); err != nil {
		return err
	}
	if err := requireRejectRouteMiss("cosigner.transfer_policy.clawback_on_no_route", tp.ClawbackOnNoRoute); err != nil {
		return err
	}
	for _, route := range tp.Routes {
		if route.Limits != nil && route.Limits.ReviewAbove != nil {
			return fmt.Errorf("cosigner.transfer_policy route %q limits.review_above is not supported; cosigner policy cannot produce review verdicts", route.ID)
		}
		for network, limits := range route.LimitsByNetwork {
			if limits.ReviewAbove != nil {
				return fmt.Errorf("cosigner.transfer_policy route %q limits_by_network[%s].review_above is not supported; cosigner policy cannot produce review verdicts", route.ID, network)
			}
		}
	}
	return nil
}

func requireRejectRouteMiss(label string, value *string) error {
	if value == nil {
		return nil
	}
	switch *value {
	case "", string(TransferOnNoRouteReject):
		return nil
	default:
		return fmt.Errorf("%s must be %q for cosigner policy, got %q", label, TransferOnNoRouteReject, *value)
	}
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

// NormalizeSigningKeyOverrideKey validates and canonicalizes a signer-domain
// policy key_overrides selector. Signer overrides are keyed by Algorand auth
// address; Witness Key IDs are valid only in cosigner-domain policy.
func NormalizeSigningKeyOverrideKey(key string) (string, error) {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return "", fmt.Errorf("signer key override selector is required")
	}
	if _, err := witness.NormalizeID(raw); err == nil {
		return "", fmt.Errorf("signer key override selector must be an Algorand auth address, not a Witness Key ID")
	}
	addr, err := types.DecodeAddress(strings.ToUpper(raw))
	if err != nil {
		return "", fmt.Errorf("signer key override selector must be an Algorand auth address")
	}
	return addr.String(), nil
}

// NormalizeCosignerKeyOverrideKey validates and canonicalizes a cosigner
// policy key_overrides selector. Cosigner overrides are always keyed by
// Witness Key ID, not spending-account address.
func NormalizeCosignerKeyOverrideKey(key string) (string, error) {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return "", fmt.Errorf("cosigner key override selector is required")
	}
	selector, err := witness.NormalizeID(raw)
	if err != nil {
		return "", fmt.Errorf("cosigner key override selector must be a Witness Key ID: %w", err)
	}
	return selector, nil
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

// PolicyPath returns the fixed product policy path.
func PolicyPath(dataRoot string) string {
	return filepath.Join(storepaths.NewPaths(dataRoot).ProductDir(), "policy.yaml")
}

// SaveStoredConfig writes the fixed product policy file atomically.
func SaveStoredConfig(dataRoot string, cfg *StoredConfig) error {
	path := PolicyPath(dataRoot)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create policy directory: %w", err)
	}

	out, err := MarshalStoredConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}

	if err := fsutil.WriteFileDurableWithProfile(path, out, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write policy config: %w", err)
	}
	return nil
}

// ParseStoredConfig parses policy YAML bytes without performing any integrity
// verification. Callers that need authoritative signer policy should use
// LoadVerifiedStoredConfig once policy integrity is enforced.
func ParseStoredConfig(data []byte) (*StoredConfig, error) {
	cfg, err := parseStoredConfig(data)
	if err != nil {
		return nil, err
	}
	if err := validateSigningDocument(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseStoredCosignerConfig parses policy.yaml bytes for a cosigner node
// without performing any integrity verification. The document is direct
// cosigner policy, with its fields at top level.
func ParseStoredCosignerConfig(data []byte) (*StoredConfig, error) {
	cfg, err := parseStoredConfig(data)
	if err != nil {
		return nil, err
	}
	if err := validateCosignerDocument(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseStoredConfig(data []byte) (*StoredConfig, error) {
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
	if err := validateSigningDocument(cfg); err != nil {
		return nil, err
	}
	return yaml.Marshal(cfg)
}

// MarshalStoredCosignerConfig serializes a whole stored cosigner policy
// config.
func MarshalStoredCosignerConfig(cfg *StoredConfig) ([]byte, error) {
	if cfg == nil {
		cfg = &StoredConfig{}
	}
	if err := validateCosignerDocument(cfg); err != nil {
		return nil, err
	}
	return yaml.Marshal(cfg)
}

// ApplySigning overlays policy.yaml values onto defaults and returns the
// effective signing policy. On signer nodes, policy.yaml is signing-only.
func (c *StoredConfig) ApplySigning(defaults *Config) (*Config, error) {
	if err := validateSigningDocument(c); err != nil {
		return nil, err
	}
	return c.Apply(defaults)
}

// ApplyCosigner overlays cosigner-node policy.yaml values onto cosigner
// defaults and returns the effective cosigner component policy. The document is
// direct: no cosigner: wrapper is used.
func (c *StoredConfig) ApplyCosigner(defaults *Config) (*Config, error) {
	if err := validateCosignerDocument(c); err != nil {
		return nil, err
	}
	base := defaultCosignerConfig(defaults)
	effective, err := applyDirectCosignerConfig(c, base)
	if err != nil {
		return nil, err
	}
	if c != nil && len(c.KeyOverrides) > 0 {
		effective.KeyOverrides, err = applyKeyOverrides(c.KeyOverrides, effective, NormalizeCosignerKeyOverrideKey, applyDirectCosignerConfig)
		if err != nil {
			return nil, err
		}
	}
	return effective, nil
}

// applyKeyOverrides resolves each stored key override over a detached copy of
// base, so an override sees only its own fields plus the identity base, never
// other overrides. normalize canonicalizes the document role's selector.
func applyKeyOverrides(
	overrides map[string]*StoredConfig,
	base *Config,
	normalize func(string) (string, error),
	apply func(*StoredConfig, *Config) (*Config, error),
) (map[string]*Config, error) {
	overrideBase := base.Clone()
	overrideBase.KeyOverrides = nil
	resolved := make(map[string]*Config, len(overrides))
	for key, overrideStored := range overrides {
		canonicalKey, err := normalize(key)
		if err != nil {
			return nil, fmt.Errorf("key_overrides for %q: %w", key, err)
		}
		if overrideStored == nil {
			continue
		}
		if _, exists := resolved[canonicalKey]; exists {
			return nil, fmt.Errorf("key_overrides for %q: duplicate canonical selector %q", key, canonicalKey)
		}
		if len(overrideStored.KeyOverrides) > 0 {
			return nil, fmt.Errorf("key_overrides for %q: nested key_overrides are not supported", canonicalKey)
		}
		overrideCfg, err := apply(overrideStored, overrideBase)
		if err != nil {
			return nil, fmt.Errorf("key_overrides for %q: %w", canonicalKey, err)
		}
		overrideCfg.KeyOverrides = nil
		resolved[canonicalKey] = overrideCfg
	}
	return resolved, nil
}

func validateSigningDocument(c *StoredConfig) error {
	if c == nil {
		return nil
	}
	if c.RejectRekey != nil {
		return fmt.Errorf("signer policy reject_rekey is not supported; use cosigner policy")
	}
	if c.RekeyPolicy != nil {
		return fmt.Errorf("signer policy rekey_policy is not supported; use cosigner policy")
	}
	for key, override := range c.KeyOverrides {
		if _, err := NormalizeSigningKeyOverrideKey(key); err != nil {
			return fmt.Errorf("key_overrides for %q: %w", key, err)
		}
		if override == nil {
			continue
		}
		if override.RejectRekey != nil {
			return fmt.Errorf("key_overrides for %q: reject_rekey is not supported in signer policy; use cosigner policy", key)
		}
		if override.RekeyPolicy != nil {
			return fmt.Errorf("key_overrides for %q: rekey_policy is not supported in signer policy; use cosigner policy", key)
		}
	}
	return nil
}

func validateCosignerDocument(c *StoredConfig) error {
	if c == nil {
		return nil
	}
	if err := validateCosignerFields(&c.StoredPolicyCore); err != nil {
		return err
	}
	for key, override := range c.KeyOverrides {
		if _, err := NormalizeCosignerKeyOverrideKey(key); err != nil {
			return fmt.Errorf("key_overrides for %q: %w", key, err)
		}
		if override == nil {
			continue
		}
		if len(override.KeyOverrides) > 0 {
			return fmt.Errorf("key_overrides for %q: nested key_overrides are not supported", key)
		}
		if err := validateCosignerFields(&override.StoredPolicyCore); err != nil {
			return fmt.Errorf("key_overrides for %q: %w", key, err)
		}
	}
	return nil
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

func applyDirectCosignerConfig(stored *StoredConfig, defaults *Config) (*Config, error) {
	if stored == nil {
		stored = &StoredConfig{}
	}
	direct := stored.Clone()
	direct.KeyOverrides = nil
	direct.TransferPolicy = normalizeCosignerTransferPolicy(direct.TransferPolicy)
	cfg, err := direct.Apply(defaults)
	if err != nil {
		return nil, err
	}
	cfg.KeyOverrides = nil
	return cfg, nil
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
	if c.RejectRekey != nil {
		effective.RejectRekey = *c.RejectRekey
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
	if c.RekeyPolicy != nil {
		compiled, err := c.RekeyPolicy.Apply(effective.RekeyPolicy, addressSetsForRekeyPolicy(effective.TransferPolicy))
		if err != nil {
			return nil, fmt.Errorf("rekey_policy: %w", err)
		}
		effective.RekeyPolicy = compiled
	}

	if len(c.KeyOverrides) > 0 {
		overrides, err := applyKeyOverrides(c.KeyOverrides, effective, NormalizeSigningKeyOverrideKey, (*StoredConfig).Apply)
		if err != nil {
			return nil, err
		}
		effective.KeyOverrides = overrides
	}

	if err := ValidateTransferGuards(effective); err != nil {
		return nil, err
	}

	return effective, nil
}

func addressSetsForRekeyPolicy(tp *TransferPolicy) map[string]compiledAddressSet {
	if tp == nil {
		return nil
	}
	return tp.AddressSets
}

func normalizeCosignerTransferPolicy(tp *StoredTransferPolicy) *StoredTransferPolicy {
	if tp == nil {
		return nil
	}
	cp := tp.Clone()
	reject := string(TransferOnNoRouteReject)
	if cp.Enabled != nil && *cp.Enabled {
		if cp.OnNoRoute == nil {
			cp.OnNoRoute = &reject
		}
		if cp.CloseOnNoRoute == nil {
			cp.CloseOnNoRoute = &reject
		}
		if cp.ClawbackOnNoRoute == nil {
			cp.ClawbackOnNoRoute = &reject
		}
	}
	return cp
}
