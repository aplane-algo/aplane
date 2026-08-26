// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
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
	Config() *serverconfig.ServerConfig
	KeyPaths() storepaths.Paths
	Theme() string
	SetTheme(v string)
	WithProcessConfigMutation(fn func() error) error
	WithStoreMutation(fn func() error) error
	SSHInfo() SSHInfo
}

type Service struct {
	Deps    Deps
	Runtime *productruntime.Runtime
}

var detectPrimaryOutboundIPv4 = primaryOutboundIPv4

func (s Service) BuildAdminSettings() adminproto.AdminSettings {
	ir := s.Runtime
	cfg := s.Deps.Config()
	sshInfo := s.Deps.SSHInfo()
	icfg := ir.Config()
	passphraseMethod := s.detectPassphraseMethod()

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
		UserAutoApprove:      icfg.UserAutoApprove(),
		LockOnDisconnect:     lockOnDisconnect,
		PassphraseTimeout:    timeoutStr,
		PassphraseMethod:     passphraseMethod,
		NodeRole:             string(ir.NodeRole()),
		SSHEnabled:           sshInfo.Enabled,
		SSHListenAddress:     cfg.Endpoint.SSH.ListenAddress,
		SSHPort:              sshInfo.Port,
		SSHFingerprint:       sshInfo.Fingerprint,
		SSHClients:           sshInfo.Clients,
		SignerPort:           cfg.Endpoint.SignerPort,
		TEALCompileNet:       cfg.TEALCompileNetwork,
		EndpointAdvertiseURL: cfg.Endpoint.AdvertiseURL,
		EndpointDisplayURL:   endpointDisplayURL(cfg, sshInfo),
		Theme:                s.Deps.Theme(),
	}
}

func endpointDisplayURL(cfg *serverconfig.ServerConfig, sshInfo SSHInfo) string {
	if cfg == nil {
		return ""
	}
	if endpoint := strings.TrimSpace(cfg.Endpoint.AdvertiseURL); endpoint != "" {
		return endpoint
	}
	if !sshInfo.Enabled || sshInfo.Port <= 0 {
		return ""
	}
	host := endpointDisplayHost(cfg.Endpoint.SSH.ListenAddress)
	if host == "" {
		host = apconfig.DefaultSSHListenAddress
	}
	return "ssh://" + net.JoinHostPort(host, strconv.Itoa(sshInfo.Port))
}

func endpointDisplayHost(listenAddress string) string {
	host := strings.TrimSpace(listenAddress)
	switch host {
	case "":
		return apconfig.DefaultSSHListenAddress
	case "0.0.0.0":
		if detected := detectPrimaryOutboundIPv4(); detected != "" {
			return detected
		}
		return apconfig.DefaultSSHListenAddress
	case "::":
		return "::1"
	default:
		return host
	}
}

func primaryOutboundIPv4() string {
	// Connected UDP asks the kernel to choose the source address for that
	// route. No application payload is sent.
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 100*time.Millisecond)
	if err != nil {
		return ""
	}
	defer func() {
		_ = conn.Close()
	}()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	ip := addr.IP.To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return ""
	}
	return ip.String()
}

func (s Service) UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error {
	if req.Key == adminproto.AdminSettingTheme {
		return s.Deps.WithProcessConfigMutation(func() error {
			return s.updateAdminSettingLocked(req)
		})
	}
	if req.Key == adminproto.AdminSettingSSHListenAddress || req.Key == adminproto.AdminSettingEndpointAdvertiseURL {
		return protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("unknown or read-only setting: %s", req.Key))
	}
	return s.Deps.WithStoreMutation(func() error {
		return s.updateAdminSettingLocked(req)
	})
}

func (s Service) updateAdminSettingLocked(req adminproto.UpdateAdminSettingRequest) error {
	ir := s.Runtime
	cfg := s.Deps.Config()

	changed, checkErr := serverconfig.ConfigFileChanged(s.Deps.DataDir(), *cfg)
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
	oldUserAutoApprove := icfg.UserAutoApprove()
	oldLockOnDisconnect := icfg.LockOnDisconnect()
	oldSessionTimeout := icfg.SessionTimeout()

	switch req.Key {
	case adminproto.AdminSettingUserAutoApprove:
		v := req.Value == "true"
		icfg.SetUserAutoApprove(v)
		saveKey, saveValue = adminproto.AdminSettingUserAutoApprove, v
	case adminproto.AdminSettingLockOnDisconnect:
		v := req.Value == "true"
		passphraseMethod := s.detectPassphraseMethod()
		if passphraseMethod != "none" && v {
			err = fmt.Errorf("cannot enable lock_on_disconnect in headless mode (passphrase method: %s)", passphraseMethod)
		} else {
			icfg.SetLockOnDisconnect(v)
			saveKey, saveValue = adminproto.AdminSettingLockOnDisconnect, v
		}
	case adminproto.AdminSettingPassphraseTimeout:
		duration, parseErr := serverconfig.ParsePassphraseTimeout(req.Value)
		if parseErr != nil {
			err = parseErr
		} else {
			passphraseMethod := s.detectPassphraseMethod()
			if passphraseMethod != "none" && duration > 0 {
				err = fmt.Errorf("cannot set passphrase_timeout in headless mode (passphrase method: %s)", passphraseMethod)
			} else {
				icfg.SetSessionTimeout(duration)
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
		err = protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("unknown or read-only setting: %s", req.Key))
	}

	if err == nil && saveKey != "" {
		mut := storemut.New(s.Deps.KeyPaths(), nil, nil)
		var saveErr error
		if saveKey == adminproto.AdminSettingTheme {
			saveErr = mut.SaveServerSetting(s.Deps.DataDir(), saveKey, saveValue)
		} else {
			saveErr = mut.SaveRuntimeSetting(s.Deps.DataDir(), saveKey, saveValue)
		}
		if saveErr != nil {
			s.Deps.SetTheme(oldTheme)
			icfg.SetUserAutoApprove(oldUserAutoApprove)
			icfg.SetLockOnDisconnect(oldLockOnDisconnect)
			icfg.SetSessionTimeout(oldSessionTimeout)
			err = fmt.Errorf("failed to save config.yaml: %w", saveErr)
		}
	}

	return err
}

type policyTargetOps struct {
	snapshotUnavailableCode string
	snapshotUnavailableErr  string
	marshal                 func(*policy.StoredConfig) ([]byte, error)
	parse                   func([]byte) (*policy.StoredConfig, error)
	loadVerified            func(active storepaths.ActivePaths, kr *crypto.Keyring) (*policy.StoredConfig, error)
	saveBytes               func(active storepaths.ActivePaths, data []byte, kr *crypto.Keyring, signedAt time.Time) error
	apply                   func(dataDir string, cfg *serverconfig.ServerConfig, stored *policy.StoredConfig) (*policy.Config, error)
	activeSnapshot          func(*productruntime.Runtime) (*policy.StoredConfig, *policy.Config)
	setState                func(*productruntime.Runtime, *policy.StoredConfig, *policy.Config)
}

func (s Service) BuildPolicySnapshot(target adminproto.PolicyTarget) adminproto.PolicySnapshot {
	ir := s.Runtime
	target = normalizeAdminPolicyTargetForNodeRole(ir.NodeRole(), target)
	ops, err := s.policyTargetOps(target)
	if err != nil {
		return policySnapshotError(target, err)
	}
	stored, _ := ops.activeSnapshot(ir)
	return canonicalPolicySnapshot(target, ops, stored)
}

func normalizeAdminPolicyTargetForNodeRole(role noderole.Role, target adminproto.PolicyTarget) adminproto.PolicyTarget {
	if target != "" {
		return target
	}
	if role == noderole.RoleSentry {
		return adminproto.PolicyTargetSentry
	}
	return adminproto.PolicyTargetSigner
}

func canonicalPolicySnapshot(target adminproto.PolicyTarget, ops policyTargetOps, stored *policy.StoredConfig) adminproto.PolicySnapshot {
	if stored == nil {
		return adminproto.PolicySnapshot{
			Success: false,
			Target:  target,
			Code:    ops.snapshotUnavailableCode,
			Error:   ops.snapshotUnavailableErr,
		}
	}
	data, err := ops.marshal(stored)
	if err != nil {
		return adminproto.PolicySnapshot{
			Success: false,
			Target:  target,
			Code:    "policy_snapshot_marshal_failed",
			Error:   err.Error(),
		}
	}
	sum := sha256.Sum256(data)
	return adminproto.PolicySnapshot{
		Success:      true,
		Target:       target,
		PolicyYAML:   string(data),
		PolicySHA256: fmt.Sprintf("%x", sum),
		Canonical:    true,
	}
}

func (s Service) policyTargetOps(target adminproto.PolicyTarget) (policyTargetOps, error) {
	if err := validatePolicyTargetForNodeRole(s.Runtime.NodeRole(), target); err != nil {
		return policyTargetOps{}, err
	}
	switch target {
	case adminproto.PolicyTargetSigner:
		return policyTargetOps{
			snapshotUnavailableCode: "policy_snapshot_unavailable",
			snapshotUnavailableErr:  "active stored policy snapshot is unavailable; reload or unlock the identity",
			marshal:                 policy.MarshalStoredConfig,
			parse:                   policy.ParseStoredConfig,
			loadVerified:            policy.LoadVerifiedStoredConfigActive,
			saveBytes:               policy.SavePolicyBytesActiveWithKeyring,
			apply:                   policyruntime.ApplyStoredConfig,
			activeSnapshot:          (*productruntime.Runtime).PolicySnapshot,
			setState: func(ir *productruntime.Runtime, stored *policy.StoredConfig, effective *policy.Config) {
				ir.SetPolicyState(stored, effective)
			},
		}, nil
	case adminproto.PolicyTargetSentry:
		return policyTargetOps{
			snapshotUnavailableCode: "sentry_policy_snapshot_unavailable",
			snapshotUnavailableErr:  "active stored sentry policy snapshot is unavailable; reload or unlock the identity",
			marshal:                 policy.MarshalStoredSentryConfig,
			parse:                   policy.ParseStoredSentryConfig,
			loadVerified:            policy.LoadVerifiedSentryConfigActive,
			saveBytes:               policy.SaveSentryBytesActiveWithKeyring,
			apply:                   policyruntime.ApplySentryStoredConfig,
			activeSnapshot:          (*productruntime.Runtime).SentryPolicySnapshot,
			setState: func(ir *productruntime.Runtime, stored *policy.StoredConfig, effective *policy.Config) {
				ir.SetSentryPolicyState(stored, effective)
			},
		}, nil
	default:
		return policyTargetOps{}, policyReplaceError{
			code: "invalid_policy_target",
			msg:  fmt.Sprintf("invalid policy target %q", target),
		}
	}
}

func validatePolicyTargetForNodeRole(role noderole.Role, target adminproto.PolicyTarget) error {
	switch target {
	case adminproto.PolicyTargetSigner:
		if role == "" || role == noderole.RoleSigner {
			return nil
		}
	case adminproto.PolicyTargetSentry:
		if role == noderole.RoleSentry {
			return nil
		}
	default:
		return policyReplaceError{
			code: "invalid_policy_target",
			msg:  fmt.Sprintf("invalid policy target %q", target),
		}
	}
	if role == "" {
		role = noderole.DefaultRole()
	}
	return policyReplaceError{
		code: "policy_target_not_allowed_for_node_role",
		msg:  fmt.Sprintf("policy target %q is not allowed on %s nodes", target, role),
	}
}

func policySnapshotError(target adminproto.PolicyTarget, err error) adminproto.PolicySnapshot {
	var replaceErr policyReplaceError
	if errors.As(err, &replaceErr) {
		return adminproto.PolicySnapshot{
			Success: false,
			Target:  target,
			Code:    replaceErr.code,
			Error:   replaceErr.msg,
		}
	}
	return adminproto.PolicySnapshot{
		Success: false,
		Target:  target,
		Code:    "policy_snapshot_failed",
		Error:   err.Error(),
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

func (s Service) ReplacePolicy(req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot {
	ir := s.Runtime
	target := normalizeAdminPolicyTargetForNodeRole(ir.NodeRole(), req.Target)
	fail := func(code, msg string) adminproto.PolicySnapshot {
		return adminproto.PolicySnapshot{
			Success: false,
			Target:  target,
			Code:    code,
			Error:   msg,
		}
	}
	ops, err := s.policyTargetOps(target)
	if err != nil {
		var replaceErr policyReplaceError
		if errors.As(err, &replaceErr) {
			return fail(replaceErr.code, replaceErr.msg)
		}
		return fail("policy_replace_failed", err.Error())
	}

	data := []byte(req.PolicyYAML)
	if strings.TrimSpace(req.PolicyYAML) == "" {
		return fail("empty_policy_yaml", "policy YAML is empty")
	}
	stored, err := ops.parse(data)
	if err != nil {
		return fail("policy_parse_failed", err.Error())
	}

	var storedSnapshot *policy.StoredConfig
	var effective *policy.Config
	err = s.Deps.WithStoreMutation(func() error {
		expectedSHA := strings.TrimSpace(req.ExpectedCurrentSHA256)
		if expectedSHA != "" {
			current := s.BuildPolicySnapshot(target)
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

		if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), kr)
			if err != nil {
				return newPolicyReplaceError(
					"policy_verify_failed",
					fmt.Errorf("resolve active generation: %w", err),
				)
			}
			if _, err := ops.loadVerified(active, kr); err != nil {
				return newPolicyReplaceError(
					"policy_verify_failed",
					fmt.Errorf("failed to verify existing %s: %w", policyTargetFileName(), err),
				)
			}
			if _, err := ops.apply(s.Deps.DataDir(), s.Deps.Config(), stored); err != nil {
				return newPolicyReplaceError("policy_validation_failed", fmt.Errorf("invalid policy: %w", err))
			}
			if err := ops.saveBytes(active, data, kr, time.Now()); err != nil {
				return newPolicyReplaceError("policy_save_failed", fmt.Errorf("failed to save %s: %w", policyTargetFileName(), err))
			}

			verified, err := ops.loadVerified(active, kr)
			if err != nil {
				return newPolicyReplaceError("policy_verify_failed", fmt.Errorf("saved policy failed verification: %w", err))
			}
			effective, err = ops.apply(s.Deps.DataDir(), s.Deps.Config(), verified)
			if err != nil {
				return newPolicyReplaceError("policy_validation_failed", fmt.Errorf("saved policy is invalid: %w", err))
			}
			storedSnapshot = verified.Clone()
			return nil
		}); err != nil {
			return err
		}
		ops.setState(ir, storedSnapshot, effective)
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

	return canonicalPolicySnapshot(target, ops, storedSnapshot)
}

func (s Service) ValidatePolicy(req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult {
	ir := s.Runtime
	target := normalizeAdminPolicyTargetForNodeRole(ir.NodeRole(), req.Target)
	fail := func(code, msg string) adminproto.ValidatePolicyResult {
		return adminproto.ValidatePolicyResult{
			Success: false,
			Target:  target,
			Code:    code,
			Error:   msg,
		}
	}
	ops, err := s.policyTargetOps(target)
	if err != nil {
		var replaceErr policyReplaceError
		if errors.As(err, &replaceErr) {
			return fail(replaceErr.code, replaceErr.msg)
		}
		return fail("policy_validation_failed", err.Error())
	}
	if strings.TrimSpace(req.PolicyYAML) == "" {
		return fail("empty_policy_yaml", "policy YAML is empty")
	}
	stored, err := ops.parse([]byte(req.PolicyYAML))
	if err != nil {
		return fail("policy_parse_failed", err.Error())
	}
	if _, err := ops.apply(s.Deps.DataDir(), s.Deps.Config(), stored); err != nil {
		return fail("policy_validation_failed", fmt.Sprintf("invalid policy: %v", err))
	}
	return adminproto.ValidatePolicyResult{
		Success: true,
		Target:  target,
	}
}

func policyTargetFileName() string {
	return "policy.yaml"
}

func (s Service) detectPassphraseMethod() string {
	unlockCfg, err := signerstartup.ResolveUnlockConfig(s.Deps.DataDir(), s.Deps.Config())
	if err != nil {
		return DetectPassphraseMethod(s.Deps.Config().PassphraseCommandArgv)
	}
	if unlockCfg != nil {
		return DetectPassphraseMethod(unlockCfg.PassphraseCommandArgv)
	}
	return "none"
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
