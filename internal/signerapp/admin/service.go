// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	algoutil "github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/asa"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storemut"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type SSHInfo struct {
	Enabled     bool
	Port        int
	Clients     int
	Fingerprint string
}

type Deps interface {
	DataDir() string
	Config() *apconfig.ServerConfig
	KeyPaths() storepaths.Paths
	Theme() string
	SetTheme(v string)
	WithProcessConfigMutation(fn func() error) error
	WithIdentityMutation(identityID string, fn func() error) error
	SSHInfo() SSHInfo
}

type Service struct {
	Deps Deps
}

func (s Service) BuildAdminSettings(ir *identity.Runtime) adminproto.AdminSettings {
	cfg := s.Deps.Config()
	sshInfo := s.Deps.SSHInfo()
	icfg := ir.Config()
	passphraseMethod := s.detectPassphraseMethodForIdentity(ir, cfg)

	timeoutStr := "0"
	if identityTimeout := icfg.SessionTimeout(); identityTimeout > 0 {
		timeoutStr = identityTimeout.String()
	}
	lockOnDisconnect := icfg.LockOnDisconnect()
	if passphraseMethod != "none" {
		timeoutStr = "0"
		lockOnDisconnect = false
	}

	return adminproto.AdminSettings{
		UserAutoApprove:   icfg.UserAutoApprove(),
		LockOnDisconnect:  lockOnDisconnect,
		PassphraseTimeout: timeoutStr,
		PassphraseMethod:  passphraseMethod,
		SSHEnabled:        sshInfo.Enabled,
		SSHPort:           sshInfo.Port,
		SSHFingerprint:    sshInfo.Fingerprint,
		SSHClients:        sshInfo.Clients,
		SignerPort:        cfg.SignerPort,
		TEALCompileNet:    cfg.TEALCompileNetwork,
		Theme:             s.Deps.Theme(),
	}
}

func (s Service) UpdateAdminSetting(ir *identity.Runtime, req adminproto.UpdateAdminSettingRequest) error {
	if req.Key == adminproto.AdminSettingTheme {
		return s.Deps.WithProcessConfigMutation(func() error {
			return s.updateAdminSettingLocked(ir, req)
		})
	}
	return s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return s.updateAdminSettingLocked(ir, req)
	})
}

func (s Service) updateAdminSettingLocked(ir *identity.Runtime, req adminproto.UpdateAdminSettingRequest) error {
	cfg := s.Deps.Config()

	changed, checkErr := apconfig.ConfigFileChanged(s.Deps.DataDir(), *cfg)
	if checkErr != nil {
		return fmt.Errorf("failed to check config file: %w", checkErr)
	}
	if changed {
		return fmt.Errorf("config.yaml has been modified externally; restart apsigner to apply changes before making further edits")
	}

	var err error
	var saveKey string
	var saveValue interface{}
	icfg := ir.Config()

	oldTheme := s.Deps.Theme()
	oldIdentityUserAutoApprove := icfg.UserAutoApprove()
	oldIdentityLockOnDisconnect := icfg.LockOnDisconnect()
	oldIdentitySessionTimeout := icfg.SessionTimeout()

	switch req.Key {
	case adminproto.AdminSettingUserAutoApprove:
		v := req.Value == "true"
		icfg.SetUserAutoApprove(v)
		saveKey, saveValue = adminproto.AdminSettingUserAutoApprove, v
	case adminproto.AdminSettingLockOnDisconnect:
		v := req.Value == "true"
		passphraseMethod := s.detectPassphraseMethodForIdentity(ir, cfg)
		if passphraseMethod != "none" && v {
			err = fmt.Errorf("cannot enable lock_on_disconnect in headless mode (passphrase method: %s)", passphraseMethod)
		} else {
			icfg.SetLockOnDisconnect(v)
			saveKey, saveValue = adminproto.AdminSettingLockOnDisconnect, v
		}
	case adminproto.AdminSettingPassphraseTimeout:
		duration, parseErr := apconfig.ParsePassphraseTimeout(req.Value)
		if parseErr != nil {
			err = parseErr
		} else {
			passphraseMethod := s.detectPassphraseMethodForIdentity(ir, cfg)
			if passphraseMethod != "none" && duration > 0 {
				err = fmt.Errorf("cannot set passphrase_timeout in headless mode (passphrase method: %s)", passphraseMethod)
			} else {
				icfg.SetSessionTimeout(duration)
				ir.SetSessionTimeout(duration)
				if duration <= 0 {
					ir.StopSessionTimer()
				} else {
					ir.ResetSessionTimer()
				}
				saveKey, saveValue = adminproto.AdminSettingPassphraseTimeout, req.Value
			}
		}
	case adminproto.AdminSettingTheme:
		v := strings.ToLower(req.Value)
		if v != "auto" && v != "dark" && v != "light" {
			err = fmt.Errorf("invalid theme %q (must be auto, dark, or light)", req.Value)
		} else {
			s.Deps.SetTheme(v)
			saveKey, saveValue = adminproto.AdminSettingTheme, v
		}
	default:
		err = fmt.Errorf("unknown or read-only setting: %s", req.Key)
	}

	if err == nil && saveKey != "" {
		mut := storemut.New(ir.ID(), s.Deps.KeyPaths(), nil, nil)
		var saveErr error
		if saveKey == adminproto.AdminSettingTheme {
			saveErr = mut.SaveServerSetting(s.Deps.DataDir(), saveKey, saveValue)
		} else {
			saveErr = mut.SaveIdentitySetting(s.Deps.DataDir(), saveKey, saveValue)
		}
		if saveErr != nil {
			s.Deps.SetTheme(oldTheme)
			icfg.SetUserAutoApprove(oldIdentityUserAutoApprove)
			icfg.SetLockOnDisconnect(oldIdentityLockOnDisconnect)
			icfg.SetSessionTimeout(oldIdentitySessionTimeout)
			ir.SetSessionTimeout(oldIdentitySessionTimeout)
			if oldIdentitySessionTimeout <= 0 {
				ir.StopSessionTimer()
			} else {
				ir.ResetSessionTimer()
			}
			err = fmt.Errorf("failed to save config.yaml: %w", saveErr)
		}
	}

	return err
}

func (s Service) BuildPolicySettings(ir *identity.Runtime) adminproto.PolicySettings {
	cfg := ir.Policy()
	if cfg == nil {
		cfg = s.defaultPolicyConfig()
	}
	reviewASAAmounts := make(map[string]string, len(cfg.ReviewASAAmounts))
	maxASAAmounts := make(map[string]string, len(cfg.MaxASAAmounts))
	metadataAmounts := make(map[string]map[uint64]uint64)
	for network, amounts := range cfg.ReviewASAAmounts {
		reviewASAAmounts[network] = s.formatPolicyASAAmounts(network, amounts)
		addPolicyASAMetadataAmounts(metadataAmounts, network, amounts)
	}
	for network, amounts := range cfg.MaxASAAmounts {
		maxASAAmounts[network] = s.formatPolicyASAAmounts(network, amounts)
		addPolicyASAMetadataAmounts(metadataAmounts, network, amounts)
	}
	policyASAMetadata := make(map[string][]adminproto.ASAMetadataInfo, len(metadataAmounts))
	for network, amounts := range metadataAmounts {
		if metadata := s.policyASAMetadata(network, amounts); len(metadata) > 0 {
			policyASAMetadata[network] = metadata
		}
	}
	policyNetworks := s.policyASANetworks()
	if policyNetworks == nil {
		policyNetworks = []string{}
	}
	reviewAlgoPayments := s.formatPolicyAlgoPayments(cfg.ReviewAlgoPayments, policyNetworks)
	maxAlgoPayments := s.formatPolicyAlgoPayments(cfg.MaxAlgoPayments, policyNetworks)
	return adminproto.PolicySettings{
		RejectForeignRekey:          cfg.RejectForeignRekey,
		RejectCloseRemainder:        cfg.RejectCloseRemainder,
		RejectAssetClose:            cfg.RejectAssetClose,
		RejectClawback:              cfg.RejectClawback,
		AlwaysReviewWarnings:        cfg.AlwaysReviewWarnings,
		AutoApproveSelfNoOpTransfer: cfg.AutoApproveSelfNoOpTransfer,
		MaxFeeMicroAlgos:            formatPolicyUint(cfg.MaxFeeMicroAlgos),
		ReviewAlgoPayments:          reviewAlgoPayments,
		MaxAlgoPayments:             maxAlgoPayments,
		PolicyNetworks:              policyNetworks,
		ReviewASAAmounts:            reviewASAAmounts,
		MaxASAAmounts:               maxASAAmounts,
		PolicyASAMetadata:           policyASAMetadata,
		MaxASAAmountsMainnet:        maxASAAmounts[apconfig.NetworkMainnet],
		MaxASAAmountsTestnet:        maxASAAmounts[apconfig.NetworkTestnet],
		MaxASAAmountsBetanet:        maxASAAmounts[apconfig.NetworkBetanet],
	}
}

func (s Service) BuildPolicySnapshot(ir *identity.Runtime) adminproto.PolicySnapshot {
	stored, _ := ir.PolicySnapshot()
	return canonicalPolicySnapshot(ir.ID(), stored)
}

func canonicalPolicySnapshot(identityID string, stored *policy.StoredConfig) adminproto.PolicySnapshot {
	if stored == nil {
		return adminproto.PolicySnapshot{
			Success:    false,
			IdentityID: identityID,
			Code:       "policy_snapshot_unavailable",
			Error:      "active stored policy snapshot is unavailable; reload or unlock the identity",
		}
	}
	data, err := policy.MarshalStoredConfig(stored)
	if err != nil {
		return adminproto.PolicySnapshot{
			Success:    false,
			IdentityID: identityID,
			Code:       "policy_snapshot_marshal_failed",
			Error:      err.Error(),
		}
	}
	sum := sha256.Sum256(data)
	return adminproto.PolicySnapshot{
		Success:      true,
		IdentityID:   identityID,
		PolicyYAML:   string(data),
		PolicySHA256: fmt.Sprintf("%x", sum),
		Canonical:    true,
	}
}

type policyReplaceError struct {
	code string
	msg  string
}

func (e policyReplaceError) Error() string {
	return e.msg
}

func newPolicyReplaceError(code string, err error) policyReplaceError {
	return policyReplaceError{code: code, msg: err.Error()}
}

func (s Service) ReplacePolicy(ir *identity.Runtime, req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot {
	fail := func(code, msg string) adminproto.PolicySnapshot {
		return adminproto.PolicySnapshot{
			Success:    false,
			IdentityID: ir.ID(),
			Code:       code,
			Error:      msg,
		}
	}

	data := []byte(req.PolicyYAML)
	if strings.TrimSpace(req.PolicyYAML) == "" {
		return fail("empty_policy_yaml", "policy YAML is empty")
	}
	stored, err := policy.ParseStoredConfig(data)
	if err != nil {
		return fail("policy_parse_failed", err.Error())
	}

	var storedSnapshot *policy.StoredConfig
	var effective *policy.Config
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		expectedSHA := strings.TrimSpace(req.ExpectedCurrentSHA256)
		if expectedSHA != "" {
			current := s.BuildPolicySnapshot(ir)
			if !current.Success {
				return policyReplaceError{code: current.Code, msg: current.Error}
			}
			if !strings.EqualFold(expectedSHA, current.PolicySHA256) {
				return policyReplaceError{
					code: "policy_snapshot_changed",
					msg:  "active policy changed; refresh the policy snapshot and try again",
				}
			}
		}

		if err := ir.WithMasterKey(func(masterKey []byte) error {
			if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.Deps.DataDir(), ir.ID(), masterKey); err != nil {
				return newPolicyReplaceError(
					"policy_verify_failed",
					fmt.Errorf("failed to verify existing policy.yaml: %w", err),
				)
			}
			if _, err := policyruntime.ApplyStoredConfig(s.Deps.DataDir(), s.Deps.Config(), stored); err != nil {
				return newPolicyReplaceError("policy_validation_failed", fmt.Errorf("invalid policy: %w", err))
			}
			if err := policy.SavePolicyBytesWithMasterKey(s.Deps.DataDir(), ir.ID(), data, masterKey, time.Now()); err != nil {
				return newPolicyReplaceError("policy_save_failed", fmt.Errorf("failed to save policy.yaml: %w", err))
			}

			verified, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.Deps.DataDir(), ir.ID(), masterKey)
			if err != nil {
				return newPolicyReplaceError("policy_verify_failed", fmt.Errorf("saved policy failed verification: %w", err))
			}
			effective, err = policyruntime.ApplyStoredConfig(s.Deps.DataDir(), s.Deps.Config(), verified)
			if err != nil {
				return newPolicyReplaceError("policy_validation_failed", fmt.Errorf("saved policy is invalid: %w", err))
			}
			storedSnapshot = verified.Clone()
			return nil
		}); err != nil {
			return err
		}
		ir.SetPolicyState(storedSnapshot, effective)
		return nil
	})
	if err != nil {
		if errors.Is(err, keystore.ErrStoreLocked) {
			return fail("identity_locked", "identity is locked; unlock signer before replacing policy")
		}
		var replaceErr policyReplaceError
		if errors.As(err, &replaceErr) {
			return fail(replaceErr.code, replaceErr.msg)
		}
		return fail("policy_replace_failed", err.Error())
	}

	return canonicalPolicySnapshot(ir.ID(), storedSnapshot)
}

func (s Service) defaultPolicyConfig() *policy.Config {
	resolver := apconfig.DefaultGenesisHashNetworkResolver()
	if cfg := s.Deps.Config(); cfg != nil {
		if configured, err := apconfig.NewGenesisHashNetworkResolver(cfg.GenesisHashNetworks); err == nil {
			resolver = configured
		}
	}
	cfg := policy.DefaultConfigWithGenesisHashResolver(resolver)
	cfg.FormatASAAmount = s.asaMetadataStore().Formatter()
	return cfg
}

func (s Service) UpdatePolicySetting(ir *identity.Runtime, req adminproto.UpdatePolicySettingRequest) error {
	return s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return s.updatePolicySettingLocked(ir, req)
	})
}

func (s Service) updatePolicySettingLocked(ir *identity.Runtime, req adminproto.UpdatePolicySettingRequest) error {
	return s.updateVerifiedPolicyLocked(ir, func(stored *policy.StoredConfig) error {
		value := strings.TrimSpace(req.Value)
		switch req.Key {
		case adminproto.PolicySettingRejectForeignRekey:
			v, parseErr := parsePolicyBool(value)
			if parseErr != nil {
				return parseErr
			}
			stored.RejectForeignRekey = &v
		case adminproto.PolicySettingRejectCloseRemainder:
			v, parseErr := parsePolicyBool(value)
			if parseErr != nil {
				return parseErr
			}
			stored.RejectCloseRemainder = &v
		case adminproto.PolicySettingRejectAssetClose:
			v, parseErr := parsePolicyBool(value)
			if parseErr != nil {
				return parseErr
			}
			stored.RejectAssetClose = &v
		case adminproto.PolicySettingRejectClawback:
			v, parseErr := parsePolicyBool(value)
			if parseErr != nil {
				return parseErr
			}
			stored.RejectClawback = &v
		case adminproto.PolicySettingAlwaysReviewWarnings:
			v, parseErr := parsePolicyBool(value)
			if parseErr != nil {
				return parseErr
			}
			stored.AlwaysReviewWarnings = &v
		case adminproto.PolicySettingAutoApproveSelfNoOpTransfer:
			v, parseErr := parsePolicyBool(value)
			if parseErr != nil {
				return parseErr
			}
			stored.AutoApproveSelfNoOpTransfer = &v
		case adminproto.PolicySettingMaxFeeMicroAlgos:
			v, parseErr := parsePolicyUint(value)
			if parseErr != nil {
				return parseErr
			}
			stored.MaxFeeMicroAlgos = &v
		case adminproto.PolicySettingMaxASAAmountsMainnet:
			parsed, parseErr := s.parsePolicyASAAmounts("mainnet", value)
			if parseErr != nil {
				return parseErr
			}
			if stored.MaxASAAmounts == nil {
				stored.MaxASAAmounts = make(map[string]map[string]uint64)
			}
			stored.MaxASAAmounts["mainnet"] = parsed
		case adminproto.PolicySettingMaxASAAmountsTestnet:
			parsed, parseErr := s.parsePolicyASAAmounts("testnet", value)
			if parseErr != nil {
				return parseErr
			}
			if stored.MaxASAAmounts == nil {
				stored.MaxASAAmounts = make(map[string]map[string]uint64)
			}
			stored.MaxASAAmounts["testnet"] = parsed
		case adminproto.PolicySettingMaxASAAmountsBetanet:
			parsed, parseErr := s.parsePolicyASAAmounts("betanet", value)
			if parseErr != nil {
				return parseErr
			}
			if stored.MaxASAAmounts == nil {
				stored.MaxASAAmounts = make(map[string]map[string]uint64)
			}
			stored.MaxASAAmounts["betanet"] = parsed
		default:
			return fmt.Errorf("unknown policy setting: %s", req.Key)
		}
		return nil
	})
}

func (s Service) UpdatePolicyASAAmounts(ir *identity.Runtime, req adminproto.UpdatePolicyASAAmountsRequest) error {
	return s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return s.updatePolicyASAAmountsLocked(ir, req)
	})
}

func (s Service) SearchASAMetadata(_ *identity.Runtime, req adminproto.SearchASAMetadataRequest) adminproto.ASAMetadataResults {
	if !s.isPolicyASANetwork(req.Network) {
		return adminproto.ASAMetadataResults{
			Network: req.Network,
			Query:   req.Query,
			Code:    "network_not_configured",
			Error:   fmt.Sprintf("ASA policy network %q is not configured with an accessible algod endpoint", req.Network),
		}
	}
	results, err := s.asaMetadataStore().SearchLocal(req.Network, req.Query)
	if err != nil {
		return adminproto.ASAMetadataResults{
			Network: req.Network,
			Query:   req.Query,
			Code:    "search_failed",
			Error:   err.Error(),
		}
	}
	out := make([]adminproto.ASAMetadataInfo, len(results))
	for i, meta := range results {
		out[i] = adminASAMetadataInfo(meta)
	}
	return adminproto.ASAMetadataResults{Network: req.Network, Query: req.Query, Results: out}
}

func (s Service) ResolveASAMetadata(_ *identity.Runtime, req adminproto.ResolveASAMetadataRequest) adminproto.ASAMetadataResult {
	if !s.isPolicyASANetwork(req.Network) {
		return adminproto.ASAMetadataResult{
			Network: req.Network,
			Code:    "network_not_configured",
			Error:   fmt.Sprintf("ASA policy network %q is not configured with an accessible algod endpoint", req.Network),
		}
	}
	meta, err := s.asaMetadataStore().MetadataByID(req.Network, req.AssetID, s.Deps.Config(), true)
	if err != nil {
		return adminproto.ASAMetadataResult{
			Network: req.Network,
			Code:    "resolve_failed",
			Error:   err.Error(),
		}
	}
	return adminproto.ASAMetadataResult{Network: req.Network, Asset: adminASAMetadataInfo(meta)}
}

func (s Service) updatePolicyASAAmountsLocked(ir *identity.Runtime, req adminproto.UpdatePolicyASAAmountsRequest) error {
	return s.updateVerifiedPolicyLocked(ir, func(stored *policy.StoredConfig) error {
		rawAmounts := cloneStringMap(req.MaxASAAmounts)
		if rawAmounts == nil {
			rawAmounts = map[string]string{
				apconfig.NetworkMainnet: req.Mainnet,
				apconfig.NetworkTestnet: req.Testnet,
				apconfig.NetworkBetanet: req.Betanet,
			}
		} else {
			if req.Mainnet != "" {
				rawAmounts[apconfig.NetworkMainnet] = req.Mainnet
			}
			if req.Testnet != "" {
				rawAmounts[apconfig.NetworkTestnet] = req.Testnet
			}
			if req.Betanet != "" {
				rawAmounts[apconfig.NetworkBetanet] = req.Betanet
			}
		}

		editableNetworks := stringSet(s.policyASANetworks())
		parsedAmounts, parseErr := s.parsePolicyASAAmountMap(rawAmounts, editableNetworks)
		if parseErr != nil {
			return parseErr
		}

		stored.MaxASAAmounts = parsedAmounts
		if req.ReviewASAAmounts != nil {
			parsedReviewAmounts, parseErr := s.parsePolicyASAAmountMap(req.ReviewASAAmounts, editableNetworks)
			if parseErr != nil {
				return parseErr
			}
			stored.ReviewASAAmounts = parsedReviewAmounts
		}
		if req.ReviewAlgoPayments != nil {
			parsedReviewAlgoPayments, parseErr := s.parsePolicyAlgoPaymentsWithLabel(req.ReviewAlgoPayments, editableNetworks, "ALGO payment review threshold")
			if parseErr != nil {
				return parseErr
			}
			stored.ReviewAlgoPayments = parsedReviewAlgoPayments
		}
		if req.MaxAlgoPayments != nil {
			parsedAlgoPayments, parseErr := s.parsePolicyAlgoPayments(req.MaxAlgoPayments, editableNetworks)
			if parseErr != nil {
				return parseErr
			}
			stored.MaxAlgoPayments = parsedAlgoPayments
		}
		return nil
	})
}

func (s Service) updateVerifiedPolicyLocked(ir *identity.Runtime, mutate func(*policy.StoredConfig) error) error {
	var effective *policy.Config
	var storedSnapshot *policy.StoredConfig
	err := ir.WithMasterKey(func(masterKey []byte) error {
		stored, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.Deps.DataDir(), ir.ID(), masterKey)
		if err != nil {
			return fmt.Errorf("failed to verify existing policy.yaml: %w", err)
		}
		if stored == nil {
			stored = &policy.StoredConfig{}
		}
		if err := mutate(stored); err != nil {
			return err
		}
		effective, err = policyruntime.SaveStoredConfigWithMasterKey(s.Deps.DataDir(), ir.ID(), s.Deps.Config(), stored, masterKey, time.Now())
		if err == nil {
			storedSnapshot = stored.Clone()
		}
		return err
	})
	if err != nil {
		if errors.Is(err, keystore.ErrStoreLocked) {
			return fmt.Errorf("identity is locked; unlock signer before editing policy")
		}
		return err
	}
	ir.SetPolicyState(storedSnapshot, effective)
	return nil
}

func (s Service) detectPassphraseMethodForIdentity(ir *identity.Runtime, cfg *apconfig.ServerConfig) string {
	unlockCfg, _ := identity.LoadUnlockConfig(s.Deps.DataDir(), ir.ID())
	if unlockCfg != nil && unlockCfg.HasPassphraseCommand() {
		return DetectPassphraseMethod(unlockCfg.PassphraseCommandArgv)
	}
	return DetectPassphraseMethod(cfg.PassphraseCommandArgv)
}

func DetectPassphraseMethod(argv []string) string {
	if len(argv) == 0 {
		return "none"
	}
	bin := argv[0]
	switch {
	case strings.HasSuffix(bin, "/appass-file") || bin == "appass-file":
		return "passfile"
	case strings.HasSuffix(bin, "/appass-systemd-creds") || bin == "appass-systemd-creds":
		return "systemd-creds"
	default:
		return "custom"
	}
}

func parsePolicyBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", raw)
	}
}

func parsePolicyUint(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid unsigned integer %q", raw)
	}
	return v, nil
}

func formatPolicyUint(v uint64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatUint(v, 10)
}

func parsePolicyAlgo(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if value == "." {
		return 0, fmt.Errorf("invalid ALGO amount %q", value)
	}
	return algoutil.ConvertTokenAmountToBaseUnits(value, 6)
}

func formatPolicyAlgo(v uint64) string {
	if v == 0 {
		return ""
	}
	return trimDecimalZeros(asa.FormatAmountWithDecimals(v, 6))
}

func trimDecimalZeros(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		return "0"
	}
	return s
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s Service) parsePolicyASAAmounts(network, raw string) (map[string]uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	pairs := strings.Split(raw, ",")
	out := make(map[string]uint64, len(pairs))
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.Split(pair, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid ASA guard %q (want asset_id:amount)", pair)
		}
		assetID := strings.TrimSpace(parts[0])
		amountRaw := strings.TrimSpace(parts[1])
		if assetID == "" {
			return nil, fmt.Errorf("invalid ASA guard %q (empty asset id)", pair)
		}

		parsedAssetID, err := strconv.ParseUint(assetID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ASA guard %q (asset id must be numeric)", pair)
		}
		meta, err := s.asaMetadataStore().MetadataByID(network, parsedAssetID, s.Deps.Config(), true)
		if err != nil {
			return nil, fmt.Errorf("asset %q on %s could not be resolved", assetID, network)
		}
		rawAmount, convErr := asa.ParseDisplayAmount(amountRaw, meta)
		if convErr != nil {
			return nil, fmt.Errorf("invalid ASA amount %q for asset %q: %w", amountRaw, assetID, convErr)
		}
		out[strconv.FormatUint(parsedAssetID, 10)] = rawAmount
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s Service) parsePolicyASAAmountMap(rawAmounts map[string]string, editableNetworks map[string]struct{}) (map[string]map[string]uint64, error) {
	parsedAmounts := make(map[string]map[string]uint64, len(rawAmounts))
	for network, raw := range rawAmounts {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid ASA policy network %q: %w", network, err)
		}
		if strings.TrimSpace(raw) == "" {
			if _, ok := editableNetworks[network]; ok {
				parsedAmounts[network] = nil
			}
			continue
		}
		if _, ok := editableNetworks[network]; !ok {
			return nil, fmt.Errorf("ASA policy network %q is not configured with an accessible algod endpoint", network)
		}
		parsed, parseErr := s.parsePolicyASAAmounts(network, raw)
		if parseErr != nil {
			return nil, parseErr
		}
		parsedAmounts[network] = parsed
	}
	return parsedAmounts, nil
}

func (s Service) policyASANetworks() []string {
	cfg := s.Deps.Config()
	if cfg == nil || len(cfg.Algod) == 0 {
		return []string{}
	}
	networks := make([]string, 0, len(cfg.Algod))
	for network, algodCfg := range cfg.Algod {
		if algodCfg == nil || strings.TrimSpace(algodCfg.Server) == "" {
			continue
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			continue
		}
		networks = append(networks, network)
	}
	sort.Strings(networks)
	return networks
}

func (s Service) isPolicyASANetwork(network string) bool {
	for _, allowed := range s.policyASANetworks() {
		if allowed == network {
			return true
		}
	}
	return false
}

func adminASAMetadataInfo(meta asa.Metadata) adminproto.ASAMetadataInfo {
	return adminproto.ASAMetadataInfo{
		AssetID:  meta.AssetID,
		Name:     meta.Name,
		UnitName: meta.UnitName,
		Decimals: meta.Decimals,
		Source:   meta.Source,
	}
}

func (s Service) policyASAMetadata(network string, amounts map[uint64]uint64) []adminproto.ASAMetadataInfo {
	if len(amounts) == 0 {
		return nil
	}
	ids := make([]uint64, 0, len(amounts))
	for assetID := range amounts {
		ids = append(ids, assetID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]adminproto.ASAMetadataInfo, 0, len(ids))
	for _, assetID := range ids {
		meta, err := s.asaMetadataStore().MetadataByID(network, assetID, s.Deps.Config(), false)
		if err != nil {
			continue
		}
		out = append(out, adminASAMetadataInfo(meta))
	}
	return out
}

func addPolicyASAMetadataAmounts(dst map[string]map[uint64]uint64, network string, amounts map[uint64]uint64) {
	if len(amounts) == 0 {
		return
	}
	if dst[network] == nil {
		dst[network] = make(map[uint64]uint64, len(amounts))
	}
	for assetID, amount := range amounts {
		dst[network][assetID] = amount
	}
}

func (s Service) formatPolicyAlgoPayments(values map[string]uint64, networks []string) map[string]string {
	out := make(map[string]string, len(networks))
	for _, network := range networks {
		if amount := values[network]; amount > 0 {
			out[network] = formatPolicyAlgo(amount)
		} else {
			out[network] = ""
		}
	}
	return out
}

func (s Service) parsePolicyAlgoPayments(raw map[string]string, editableNetworks map[string]struct{}) (map[string]uint64, error) {
	return s.parsePolicyAlgoPaymentsWithLabel(raw, editableNetworks, "ALGO payment max")
}

func (s Service) parsePolicyAlgoPaymentsWithLabel(raw map[string]string, editableNetworks map[string]struct{}, label string) (map[string]uint64, error) {
	out := make(map[string]uint64, len(raw))
	for network, value := range raw {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return nil, fmt.Errorf("invalid ALGO policy network %q: %w", network, err)
		}
		if _, ok := editableNetworks[network]; !ok {
			return nil, fmt.Errorf("ALGO policy network %q is not configured with an accessible algod endpoint", network)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		amount, err := parsePolicyAlgo(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s for %s: %w", label, network, err)
		}
		if amount > 0 {
			out[network] = amount
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func (s Service) formatPolicyASAAmounts(network string, m map[uint64]uint64) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	ids := make([]uint64, 0, len(m))
	for assetID := range m {
		ids = append(ids, assetID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, assetID := range ids {
		assetRef := strconv.FormatUint(assetID, 10)
		amount := strconv.FormatUint(m[assetID], 10)
		if meta, err := s.asaMetadataStore().MetadataByID(network, assetID, s.Deps.Config(), false); err == nil {
			amount = asa.FormatDisplayAmount(m[assetID], meta)
		}
		parts = append(parts, fmt.Sprintf("%s:%s", assetRef, amount))
	}
	return strings.Join(parts, ", ")
}

func (s Service) asaMetadataStore() asametadata.Store {
	return asametadata.NewStore(s.Deps.DataDir())
}
