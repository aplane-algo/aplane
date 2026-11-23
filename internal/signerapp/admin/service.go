// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type SSHInfo struct {
	Port        int
	Clients     int
	Fingerprint string
}

type Deps interface {
	DataDir() string
	Config() *serverconfig.ServerConfig
	KeyPaths() storepaths.Paths
	WithStoreMutation(fn func() error) error
	SSHInfo() SSHInfo
	// Warnf logs an operator-facing warning to the signer's log.
	Warnf(format string, args ...any)
}

// SettingAudit records admin setting mutations. Non-restrictive changes
// require a durable intent record before the setting is saved or published;
// restrictive changes never block on audit availability or writes.
type SettingAudit interface {
	LogSettingChangeIntentDurable(ctx context.Context, operationID, key, oldValue, newValue string) error
	LogSettingChanged(ctx context.Context, operationID, key, oldValue, newValue string)
}

type Service struct {
	Deps    Deps
	Runtime *productruntime.Runtime
	// ASAChain is the node's network mapping and reads assets for the ASA
	// set.
	ASAChain ASAChain
	// Audit records setting mutations. A nil Audit refuses non-restrictive
	// setting changes (audit_unavailable) while still allowing restrictive
	// changes so an audit failure never blocks locking down.
	Audit SettingAudit
	// Now is the clock for ASA set changes; nil is time.Now.
	Now func() time.Time
}

var detectPrimaryOutboundIPv4 = primaryOutboundIPv4

func (s Service) BuildAdminSettings() adminproto.AdminSettings {
	ir := s.Runtime
	cfg := s.Deps.Config()
	sshInfo := s.Deps.SSHInfo()
	icfg := ir.Config()
	passphraseMethod := ir.UnlockMethod()

	timeoutStr := formatSessionTimeout(icfg.SessionTimeout())
	// The runtime holds what startup decided: the unlock method, and the
	// timeout and lock-on-disconnect a helper forces. unlock.yaml may have
	// changed since and takes effect at the next start.
	lockOnDisconnect := icfg.LockOnDisconnect()

	requireContained, requireCosigner := icfg.GenerationRequirements()
	return adminproto.AdminSettings{
		UnsavedSettings:      icfg.UnsavedSettings(),
		UserAutoApprove:      icfg.UserAutoApprove(),
		RequireContained:     requireContained,
		RequireCosigner:      requireCosigner,
		LockOnDisconnect:     lockOnDisconnect,
		PassphraseTimeout:    timeoutStr,
		PassphraseMethod:     passphraseMethod,
		NodeRole:             string(ir.NodeRole()),
		SSHListenAddress:     cfg.Endpoint.SSH.ListenAddress,
		SSHPort:              sshInfo.Port,
		SSHFingerprint:       sshInfo.Fingerprint,
		SSHClients:           sshInfo.Clients,
		SignerPort:           cfg.Endpoint.SignerPort,
		TEALCompileNet:       cfg.TEALCompileNetwork,
		EndpointAdvertiseURL: cfg.Endpoint.AdvertiseURL,
		EndpointDisplayURL:   endpointDisplayURL(cfg, sshInfo),
		Theme:                icfg.Theme(),
	}
}

func endpointDisplayURL(cfg *serverconfig.ServerConfig, sshInfo SSHInfo) string {
	if endpoint := strings.TrimSpace(cfg.Endpoint.AdvertiseURL); endpoint != "" {
		return endpoint
	}
	if sshInfo.Port <= 0 {
		return ""
	}
	host := endpointDisplayHost(cfg.Endpoint.SSH.ListenAddress)
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

func formatSessionTimeout(d time.Duration) string {
	if d > 0 {
		return d.String()
	}
	return "0"
}

type parsedAdminSetting struct {
	oldValue    string
	newValue    string
	saveValue   interface{}
	publish     func()
	restrictive bool
}

func (s Service) parseAdminSetting(icfg *productruntime.RuntimeConfig, req adminproto.UpdateAdminSettingRequest, unsaved bool) (parsedAdminSetting, error) {
	switch req.Key {
	case adminproto.AdminSettingRequireContained:
		v, err := parseBoolSetting(req)
		if err != nil {
			return parsedAdminSetting{}, err
		}
		contained, cosigner := icfg.GenerationRequirements()
		return parsedAdminSetting{
			oldValue:    strconv.FormatBool(contained),
			newValue:    strconv.FormatBool(v),
			saveValue:   v,
			publish:     func() { icfg.SetGenerationRequirements(v, cosigner) },
			restrictive: restricts(true, v, contained, unsaved),
		}, nil
	case adminproto.AdminSettingRequireCosigner:
		v, err := parseBoolSetting(req)
		if err != nil {
			return parsedAdminSetting{}, err
		}
		contained, cosigner := icfg.GenerationRequirements()
		return parsedAdminSetting{
			oldValue:    strconv.FormatBool(cosigner),
			newValue:    strconv.FormatBool(v),
			saveValue:   v,
			publish:     func() { icfg.SetGenerationRequirements(contained, v) },
			restrictive: restricts(true, v, cosigner, unsaved),
		}, nil
	case adminproto.AdminSettingUserAutoApprove:
		v, err := parseBoolSetting(req)
		if err != nil {
			return parsedAdminSetting{}, err
		}
		cur := icfg.UserAutoApprove()
		return parsedAdminSetting{
			oldValue:    strconv.FormatBool(cur),
			newValue:    strconv.FormatBool(v),
			saveValue:   v,
			publish:     func() { icfg.SetUserAutoApprove(v) },
			restrictive: restricts(false, v, cur, unsaved),
		}, nil
	case adminproto.AdminSettingLockOnDisconnect:
		v, err := parseBoolSetting(req)
		if err != nil {
			return parsedAdminSetting{}, err
		}
		if passphraseMethod := s.Runtime.UnlockMethod(); passphraseMethod != unlockconfig.MethodNone && v {
			return parsedAdminSetting{}, fmt.Errorf("cannot enable lock_on_disconnect in headless mode (passphrase method: %s)", passphraseMethod)
		}
		cur := icfg.LockOnDisconnect()
		return parsedAdminSetting{
			oldValue:    strconv.FormatBool(cur),
			newValue:    strconv.FormatBool(v),
			saveValue:   v,
			publish:     func() { icfg.SetLockOnDisconnect(v) },
			restrictive: restricts(true, v, cur, unsaved),
		}, nil
	case adminproto.AdminSettingPassphraseTimeout:
		// Only the admin client enforces the timeout, so publishing it early
		// would change nothing in the signer: it is never restrictive.
		duration, err := serverconfig.ParsePassphraseTimeout(req.Value)
		if err != nil {
			return parsedAdminSetting{}, err
		}
		if passphraseMethod := s.Runtime.UnlockMethod(); passphraseMethod != unlockconfig.MethodNone && duration > 0 {
			return parsedAdminSetting{}, fmt.Errorf("cannot set passphrase_timeout in headless mode (passphrase method: %s)", passphraseMethod)
		}
		return parsedAdminSetting{
			oldValue:  formatSessionTimeout(icfg.SessionTimeout()),
			newValue:  formatSessionTimeout(duration),
			saveValue: req.Value,
			publish:   func() { icfg.SetSessionTimeout(duration) },
		}, nil
	case adminproto.AdminSettingTheme:
		v := strings.ToLower(req.Value)
		if v != "auto" && v != "dark" && v != "light" {
			return parsedAdminSetting{}, fmt.Errorf("invalid theme %q (must be auto, dark, or light)", req.Value)
		}
		return parsedAdminSetting{
			oldValue:  icfg.Theme(),
			newValue:  v,
			saveValue: v,
			publish:   func() { icfg.SetTheme(v) },
		}, nil
	default:
		return parsedAdminSetting{}, protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("unknown or read-only setting: %s", req.Key))
	}
}

func (s Service) recordSettingIntentDurable(ctx context.Context, operationID, key, oldValue, newValue string) error {
	if s.Audit == nil {
		return protocol.WithCode(protocol.ResultCodeAuditUnavailable,
			fmt.Errorf("setting update refused: the daemon has no audit log, because it could not be opened at startup (see the daemon log). Repair the audit log's storage or permissions, then restart the daemon; retrying the request alone cannot help"))
	}
	if err := s.Audit.LogSettingChangeIntentDurable(ctx, operationID, key, oldValue, newValue); err != nil {
		return protocol.WithCode(protocol.ResultCodeAuditWriteFailed,
			fmt.Errorf("setting update refused: the audit log could not record the request: %w. Repair the cause, such as a full disk or wrong permissions, and retry", err))
	}
	return nil
}

func (s Service) UpdateAdminSetting(ctx context.Context, req adminproto.UpdateAdminSettingRequest) error {
	return s.Deps.WithStoreMutation(func() error {
		return s.updateAdminSettingLocked(ctx, req)
	})
}

func (s Service) updateAdminSettingLocked(ctx context.Context, req adminproto.UpdateAdminSettingRequest) error {
	icfg := s.Runtime.Config()
	unsaved := icfg.IsUnsaved(req.Key)

	// The new value is a candidate until it is published. A restrictive one
	// (see restricts) is published before the save, so it is in effect for
	// as long as the save takes and stays in effect if the save fails, and
	// never waits on the audit log so an audit failure cannot block locking
	// down. Any other value (loosening a boolean setting, theme,
	// passphrase_timeout, or a value already saved) waits for a durable
	// intent record before saving and is published only once the save
	// returns, so no reader, a signing request included, ever sees a
	// permissive value that was not audited and saved.
	parsed, err := s.parseAdminSetting(icfg, req, unsaved)
	if err != nil {
		return err
	}

	if parsed.restrictive {
		// In effect and ahead of the file until the save puts the new file
		// in place, which clears it below: a save that hangs leaves it
		// reported unsaved.
		parsed.publish()
		icfg.SetUnsaved(req.Key, true)
	} else if err := s.recordSettingIntentDurable(ctx, req.OperationID, req.Key, parsed.oldValue, parsed.newValue); err != nil {
		return err
	}

	// The save rewrites only this key of the product runtime config: an
	// edit to another key of the file made while the signer runs stays in
	// the file and takes effect at the next start. The process-global
	// config.yaml is never written.
	saveErr := productruntime.SaveStoredSetting(s.Deps.DataDir(), req.Key, parsed.saveValue)
	switch {
	case saveErr == nil || errors.Is(saveErr, fsutil.ErrPublishedNotDurable):
		// The new file is in place and is what the next start loads, so
		// memory follows it (a restrictive value already does) and is no
		// longer ahead of it. The directory flush after the rename is best
		// effort: its failure does not say the change missed the disk, so
		// it is a success, logged because it points at a failing disk.
		parsed.publish()
		icfg.SetUnsaved(req.Key, false)
		if s.Audit != nil {
			s.Audit.LogSettingChanged(ctx, req.OperationID, req.Key, parsed.oldValue, parsed.newValue)
		}
		if saveErr != nil {
			s.Deps.Warnf("setting %s saved, but its directory flush failed: %v", req.Key, saveErr)
		}
		return nil
	case parsed.restrictive:
		// The old file is still in place. Memory keeps the restrictive value
		// rather than go back to the permissive one it replaced, and the
		// signer reports the setting unsaved until a save of it succeeds.
		return protocol.WithCode(protocol.ResultCodeAppliedNotSaved,
			&adminproto.SettingSaveError{Key: req.Key, Value: fmt.Sprint(parsed.saveValue), InEffect: true, Err: saveErr})
	default:
		return &adminproto.SettingSaveError{Key: req.Key, Value: fmt.Sprint(parsed.saveValue), Err: saveErr}
	}
}

// restricts reports whether a request for boolean setting value requested is
// restrictive, current being the value in effect: requested is the
// setting's restrictive value (restrictiveValue), and it differs from the
// value in effect or the setting is unsaved (in effect ahead of the file, so
// the request retries the save).
func restricts(restrictiveValue, requested, current, unsaved bool) bool {
	return requested == restrictiveValue && (current != restrictiveValue || unsaved)
}

// parseBoolSetting accepts exactly "true" or "false" for a boolean setting.
func parseBoolSetting(req adminproto.UpdateAdminSettingRequest) (bool, error) {
	switch req.Value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, protocol.WithCode(protocol.ErrCodeInvalidRequest,
		fmt.Errorf("invalid %s value %q (must be true or false)", req.Key, req.Value))
}
