// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
)

// Config is the effective signer-side policy for one identity.
//
// KeyOverrides maps a concrete signing authority key to a fully resolved Config
// that should be used when that key signs. Signing account overrides are keyed
// by Algorand auth address. Sentry component overrides are keyed by component
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
	Sentry                      *Config
	GenesisHashResolver         apconfig.GenesisHashNetworkResolver
	FormatASAAmount             func(network string, assetID uint64, raw uint64) (string, bool)
}

// StoredConfig is the persisted YAML representation for identity-scoped policy.
// Nil booleans mean "use default". Zero threshold values mean "no limit".
// KeyOverrides is a map from concrete signing authority key to a sparse
// StoredConfig that is layered on top of the identity-wide settings when that
// key signs. Overrides never recurse.
type StoredConfig struct {
	StoredPolicyCore `yaml:",inline"`

	ClientSigning *StoredRoleConfig        `yaml:"client_signing,omitempty"`
	Sentry        *StoredRoleConfig        `yaml:"sentry,omitempty"`
	KeyOverrides  map[string]*StoredConfig `yaml:"key_overrides,omitempty"`
}

// StoredRoleConfig is a sparse role-domain policy block nested under
// client_signing: or sentry:. It intentionally does not recurse into role
// blocks or key_overrides.
type StoredRoleConfig struct {
	StoredPolicyCore `yaml:",inline"`
}

// StoredPolicyCore is the policy field block shared by StoredConfig and
// StoredRoleConfig. Adding a field here (plus storedPolicyCoreFields below)
// extends both the identity-wide document and the role-domain blocks in one
// place.
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
// unmarshal allow-lists. Keep in sync with the struct tags above.
var storedPolicyCoreFields = []string{
	"reject_rekey",
	"reject_foreign_rekey",
	"reject_close_remainder",
	"reject_asset_close",
	"reject_clawback",
	"always_review_warnings",
	"auto_approve_self_noop_transfer",
	"max_fee_microalgos",
	"review_algo_payments",
	"max_algo_payments",
	"review_asa_amounts",
	"max_asa_amounts",
	"transfer_policy",
	"rekey_policy",
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
	cp.ClientSigning = c.ClientSigning.Clone()
	cp.Sentry = c.Sentry.Clone()
	if c.KeyOverrides != nil {
		cp.KeyOverrides = make(map[string]*StoredConfig, len(c.KeyOverrides))
		for key, override := range c.KeyOverrides {
			cp.KeyOverrides[key] = override.Clone()
		}
	}
	return &cp
}

func (c *StoredRoleConfig) Clone() *StoredRoleConfig {
	if c == nil {
		return nil
	}
	return &StoredRoleConfig{StoredPolicyCore: *c.StoredPolicyCore.Clone()}
}

func (c *StoredConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("policy config must be a mapping")
	}
	allowed := allowedFieldSet("client_signing", "sentry", "key_overrides")
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
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
	if err := validateRoleConfig("client_signing", c.ClientSigning); err != nil {
		return err
	}
	if err := validateRoleConfig("sentry", c.Sentry); err != nil {
		return err
	}
	return nil
}

func (c *StoredRoleConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("policy role config must be a mapping")
	}
	allowed := allowedFieldSet()
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown policy role field %q", key)
		}
	}
	type rawRoleConfig StoredRoleConfig
	var raw rawRoleConfig
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*c = StoredRoleConfig(raw)
	return nil
}

func validateRoleConfig(role string, cfg *StoredRoleConfig) error {
	if cfg == nil {
		return nil
	}
	switch role {
	case "client_signing":
		if cfg.RejectRekey != nil {
			return fmt.Errorf("client_signing.reject_rekey is not supported; reject_rekey is sentry-only")
		}
		if cfg.RekeyPolicy != nil {
			return fmt.Errorf("client_signing.rekey_policy is not supported; rekey_policy is sentry-only")
		}
	case "sentry":
		if cfg.RejectForeignRekey != nil {
			return fmt.Errorf("sentry.reject_foreign_rekey is not supported; use sentry.reject_rekey")
		}
		if cfg.AlwaysReviewWarnings != nil {
			return fmt.Errorf("sentry.always_review_warnings is not supported; sentry policy cannot produce review verdicts")
		}
		if cfg.AutoApproveSelfNoOpTransfer != nil {
			return fmt.Errorf("sentry.auto_approve_self_noop_transfer is not supported; sentry has no operator default")
		}
		if len(cfg.ReviewAlgoPayments) > 0 {
			return fmt.Errorf("sentry.review_algo_payments is not supported; sentry policy cannot produce review verdicts")
		}
		if len(cfg.ReviewASAAmounts) > 0 {
			return fmt.Errorf("sentry.review_asa_amounts is not supported; sentry policy cannot produce review verdicts")
		}
		if err := validateSentryTransferPolicy(cfg.TransferPolicy); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown policy role %q", role)
	}
	return nil
}

func validateSentryTransferPolicy(tp *StoredTransferPolicy) error {
	if tp == nil {
		return nil
	}
	if err := requireRejectRouteMiss("sentry.transfer_policy.on_no_route", tp.OnNoRoute); err != nil {
		return err
	}
	if err := requireRejectRouteMiss("sentry.transfer_policy.close_on_no_route", tp.CloseOnNoRoute); err != nil {
		return err
	}
	if err := requireRejectRouteMiss("sentry.transfer_policy.clawback_on_no_route", tp.ClawbackOnNoRoute); err != nil {
		return err
	}
	for _, route := range tp.Routes {
		if route.Limits != nil && route.Limits.ReviewAbove != nil {
			return fmt.Errorf("sentry.transfer_policy route %q limits.review_above is not supported; sentry policy cannot produce review verdicts", route.ID)
		}
		for network, limits := range route.LimitsByNetwork {
			if limits.ReviewAbove != nil {
				return fmt.Errorf("sentry.transfer_policy route %q limits_by_network[%s].review_above is not supported; sentry policy cannot produce review verdicts", route.ID, network)
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
		return fmt.Errorf("%s must be %q for sentry policy, got %q", label, TransferOnNoRouteReject, *value)
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
	if c.Sentry != nil {
		cp.Sentry = c.Sentry.Clone()
		if cp.Sentry != nil {
			cp.Sentry.Sentry = nil
		}
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
// It accepts both signer auth addresses and Sentry Key IDs because Config.ForKey
// is shared by signer and sentry effective policy snapshots. Policy document
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
		return "", fmt.Errorf("invalid Sentry Key ID %q", raw)
	}
	addr, err := types.DecodeAddress(strings.ToUpper(raw))
	if err != nil {
		return "", fmt.Errorf("key override selector must be an Algorand address or Sentry Key ID")
	}
	return addr.String(), nil
}

// NormalizeSigningKeyOverrideKey validates and canonicalizes a signer-domain
// policy key_overrides selector. Signer overrides are keyed by Algorand auth
// address; Sentry Key IDs are valid only in sentry-domain policy.
func NormalizeSigningKeyOverrideKey(key string) (string, error) {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return "", fmt.Errorf("signer key override selector is required")
	}
	if _, err := witness.NormalizeID(raw); err == nil {
		return "", fmt.Errorf("signer key override selector must be an Algorand auth address, not a Sentry Key ID")
	}
	addr, err := types.DecodeAddress(strings.ToUpper(raw))
	if err != nil {
		return "", fmt.Errorf("signer key override selector must be an Algorand auth address")
	}
	return addr.String(), nil
}

// NormalizeSentryKeyOverrideKey validates and canonicalizes a sentry
// policy key_overrides selector. Sentry overrides are always keyed by
// Sentry Key ID, not spending-account address.
func NormalizeSentryKeyOverrideKey(key string) (string, error) {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return "", fmt.Errorf("sentry key override selector is required")
	}
	selector, err := witness.NormalizeID(raw)
	if err != nil {
		return "", fmt.Errorf("sentry key override selector must be a Sentry Key ID: %w", err)
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

// PolicyPath returns the path to an identity policy file.
func PolicyPath(dataRoot, identityID string) string {
	return filepath.Join(dataRoot, "identities", identityID, "policy.yaml")
}

// SentryPath returns the path to the policy file used by sentry nodes.
// Single-mode nodes store the active role policy in policy.yaml; this helper is
// retained so sentry-domain callers can keep using the sentry parser and
// validator without carrying a separate filename.
func SentryPath(dataRoot, identityID string) string {
	return PolicyPath(dataRoot, identityID)
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
	cfg, err := parseStoredConfig(data)
	if err != nil {
		return nil, err
	}
	if err := validateSigningDocument(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseStoredSentryConfig parses policy.yaml bytes for a sentry node
// without performing any integrity verification. The document is direct
// sentry policy; it must not contain a sentry: wrapper.
func ParseStoredSentryConfig(data []byte) (*StoredConfig, error) {
	cfg, err := parseStoredConfig(data)
	if err != nil {
		return nil, err
	}
	if err := validateSentryDocument(cfg); err != nil {
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

// MarshalStoredSentryConfig serializes a whole stored sentry policy
// config.
func MarshalStoredSentryConfig(cfg *StoredConfig) ([]byte, error) {
	if cfg == nil {
		cfg = &StoredConfig{}
	}
	if err := validateSentryDocument(cfg); err != nil {
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
	effective, err := c.Apply(defaults)
	if err != nil {
		return nil, err
	}
	effective.Sentry = nil
	return effective, nil
}

// ApplySentry overlays sentry-node policy.yaml values onto sentry
// defaults and returns the effective sentry component policy. The document is
// direct: no sentry: wrapper is used.
func (c *StoredConfig) ApplySentry(defaults *Config) (*Config, error) {
	if err := validateSentryDocument(c); err != nil {
		return nil, err
	}
	base := defaultSentryConfig(defaults)
	effective, err := applyDirectSentryConfig(c, base)
	if err != nil {
		return nil, err
	}
	if c != nil && len(c.KeyOverrides) > 0 {
		overrideBase := effective.Clone()
		overrideBase.KeyOverrides = nil
		effective.KeyOverrides = make(map[string]*Config, len(c.KeyOverrides))
		for key, overrideStored := range c.KeyOverrides {
			if overrideStored == nil {
				continue
			}
			canonicalKey, normalizeErr := NormalizeSentryKeyOverrideKey(key)
			if normalizeErr != nil {
				return nil, fmt.Errorf("key_overrides for %q: %w", key, normalizeErr)
			}
			if _, exists := effective.KeyOverrides[canonicalKey]; exists {
				return nil, fmt.Errorf("key_overrides for %q: duplicate canonical selector %q", key, canonicalKey)
			}
			overrideCfg, err := applyDirectSentryConfig(overrideStored, overrideBase)
			if err != nil {
				return nil, fmt.Errorf("key_overrides for %q: %w", canonicalKey, err)
			}
			overrideCfg.KeyOverrides = nil
			effective.KeyOverrides[canonicalKey] = overrideCfg
		}
	}
	return effective, nil
}

func validateSigningDocument(c *StoredConfig) error {
	if c == nil {
		return nil
	}
	if c.RejectRekey != nil {
		return fmt.Errorf("signer policy reject_rekey is not supported; use sentry policy")
	}
	if c.RekeyPolicy != nil {
		return fmt.Errorf("signer policy rekey_policy is not supported; use sentry policy")
	}
	if c.Sentry != nil {
		return fmt.Errorf("signer policy sentry is not supported; use sentry policy")
	}
	for key, override := range c.KeyOverrides {
		if _, err := NormalizeSigningKeyOverrideKey(key); err != nil {
			return fmt.Errorf("key_overrides for %q: %w", key, err)
		}
		if override == nil {
			continue
		}
		if override.RejectRekey != nil {
			return fmt.Errorf("key_overrides for %q: reject_rekey is not supported in signer policy; use sentry policy", key)
		}
		if override.RekeyPolicy != nil {
			return fmt.Errorf("key_overrides for %q: rekey_policy is not supported in signer policy; use sentry policy", key)
		}
		if override.Sentry != nil {
			return fmt.Errorf("key_overrides for %q: sentry is not supported in signer policy; use sentry policy", key)
		}
	}
	return nil
}

func validateSentryDocument(c *StoredConfig) error {
	if c == nil {
		return nil
	}
	if c.ClientSigning != nil {
		return fmt.Errorf("sentry policy client_signing is not supported")
	}
	if c.Sentry != nil {
		return fmt.Errorf("sentry policy must not contain a sentry wrapper; put sentry policy fields at top level")
	}
	if err := validateRoleConfig("sentry", c.toStoredRoleConfig()); err != nil {
		return err
	}
	for key, override := range c.KeyOverrides {
		if _, err := NormalizeSentryKeyOverrideKey(key); err != nil {
			return fmt.Errorf("key_overrides for %q: %w", key, err)
		}
		if override == nil {
			continue
		}
		if override.ClientSigning != nil {
			return fmt.Errorf("key_overrides for %q: client_signing is not supported in sentry policy", key)
		}
		if override.Sentry != nil {
			return fmt.Errorf("key_overrides for %q: sentry wrapper is not supported in sentry policy", key)
		}
		if len(override.KeyOverrides) > 0 {
			return fmt.Errorf("key_overrides for %q: nested key_overrides are not supported", key)
		}
		if err := validateRoleConfig("sentry", override.toStoredRoleConfig()); err != nil {
			return fmt.Errorf("key_overrides for %q: %w", key, err)
		}
	}
	return nil
}

func defaultSentryConfig(defaults *Config) *Config {
	base := DefaultConfig()
	if defaults != nil {
		base = DefaultConfigWithGenesisHashResolver(defaults.GenesisHashResolver)
		base.FormatASAAmount = defaults.FormatASAAmount
	}
	base.RejectForeignRekey = false
	base.RejectRekey = false
	return base
}

func applyDirectSentryConfig(stored *StoredConfig, defaults *Config) (*Config, error) {
	if stored == nil {
		stored = &StoredConfig{}
	}
	direct := stored.Clone()
	direct.ClientSigning = nil
	direct.Sentry = nil
	direct.KeyOverrides = nil
	direct.TransferPolicy = normalizeSentryTransferPolicy(direct.TransferPolicy)
	cfg, err := direct.Apply(defaults)
	if err != nil {
		return nil, err
	}
	cfg.Sentry = nil
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
	if err := validateRoleConfig("client_signing", c.ClientSigning); err != nil {
		return nil, err
	}
	if err := validateRoleConfig("sentry", c.Sentry); err != nil {
		return nil, err
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

	if c.ClientSigning != nil {
		clientSigningCfg, err := c.ClientSigning.toStoredConfig().Apply(effective)
		if err != nil {
			return nil, fmt.Errorf("client_signing: %w", err)
		}
		effective = clientSigningCfg
	}

	sentryCfg, err := c.applySentry(effective)
	if err != nil {
		return nil, err
	}
	effective.Sentry = sentryCfg

	if len(c.KeyOverrides) > 0 {
		// Use a detached copy of the resolved base as the "defaults" for each
		// override so overrides only see their own fields plus the identity
		// base, never other overrides.
		overrideBase := effective.Clone()
		overrideBase.KeyOverrides = nil
		effective.KeyOverrides = make(map[string]*Config, len(c.KeyOverrides))
		for key, overrideStored := range c.KeyOverrides {
			canonicalKey, normalizeErr := NormalizeSigningKeyOverrideKey(key)
			if normalizeErr != nil {
				return nil, fmt.Errorf("key_overrides for %q: %w", key, normalizeErr)
			}
			if overrideStored == nil {
				continue
			}
			if _, exists := effective.KeyOverrides[canonicalKey]; exists {
				return nil, fmt.Errorf("key_overrides for %q: duplicate canonical selector %q", key, canonicalKey)
			}
			if len(overrideStored.KeyOverrides) > 0 {
				return nil, fmt.Errorf("key_overrides for %q: nested key_overrides are not supported", canonicalKey)
			}
			overrideCfg, err := overrideStored.Apply(overrideBase)
			if err != nil {
				return nil, fmt.Errorf("key_overrides for %q: %w", canonicalKey, err)
			}
			overrideCfg.KeyOverrides = nil
			effective.KeyOverrides[canonicalKey] = overrideCfg
		}
	}

	if err := ValidateTransferGuards(effective); err != nil {
		return nil, err
	}

	return effective, nil
}

func (c *StoredConfig) applySentry(clientEffective *Config) (*Config, error) {
	if c == nil || c.Sentry == nil {
		if clientEffective != nil && clientEffective.Sentry != nil {
			return clientEffective.Sentry.Clone(), nil
		}
		return nil, nil
	}
	var base *Config
	if clientEffective.Sentry != nil {
		base = clientEffective.Sentry.Clone()
	} else {
		base = DefaultConfigWithGenesisHashResolver(clientEffective.GenesisHashResolver)
		base.FormatASAAmount = clientEffective.FormatASAAmount
		base.RejectRekey = false
	}
	common := c.commonStoredConfig()
	cfg, err := common.Apply(base)
	if err != nil {
		return nil, fmt.Errorf("sentry common policy: %w", err)
	}
	roleStored := c.Sentry.toStoredConfig()
	if roleStored.TransferPolicy != nil {
		roleStored.TransferPolicy = normalizeSentryTransferPolicy(roleStored.TransferPolicy)
	}
	cfg, err = roleStored.Apply(cfg)
	if err != nil {
		return nil, fmt.Errorf("sentry: %w", err)
	}
	cfg.KeyOverrides = nil
	cfg.Sentry = nil
	return cfg, nil
}

func (c *StoredConfig) commonStoredConfig() *StoredConfig {
	if c == nil {
		return &StoredConfig{}
	}
	return &StoredConfig{StoredPolicyCore: StoredPolicyCore{
		RejectCloseRemainder: c.RejectCloseRemainder,
		RejectAssetClose:     c.RejectAssetClose,
		RejectClawback:       c.RejectClawback,
		MaxFeeMicroAlgos:     c.MaxFeeMicroAlgos,
		MaxAlgoPayments:      cloneUintMap(c.MaxAlgoPayments),
		MaxASAAmounts:        cloneStoredASAAmounts(c.MaxASAAmounts),
		TransferPolicy:       normalizeSentryTransferPolicy(c.TransferPolicy),
	}}
}

func addressSetsForRekeyPolicy(tp *TransferPolicy) map[string]compiledAddressSet {
	if tp == nil {
		return nil
	}
	return tp.AddressSets
}

func (c *StoredRoleConfig) toStoredConfig() *StoredConfig {
	if c == nil {
		return &StoredConfig{}
	}
	return &StoredConfig{StoredPolicyCore: *c.StoredPolicyCore.Clone()}
}

func (c *StoredConfig) toStoredRoleConfig() *StoredRoleConfig {
	if c == nil {
		return nil
	}
	return &StoredRoleConfig{StoredPolicyCore: *c.StoredPolicyCore.Clone()}
}

func normalizeSentryTransferPolicy(tp *StoredTransferPolicy) *StoredTransferPolicy {
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
