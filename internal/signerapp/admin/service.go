// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
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
	WithStoreMutation(fn func() error) error
	SSHInfo() SSHInfo
	// Warnf logs an operator-facing warning to the signer's log.
	Warnf(format string, args ...any)
}

type Service struct {
	Deps    Deps
	Runtime *productruntime.Runtime
	// ASAChain is the node's network mapping and reads assets for the ASA
	// set.
	ASAChain ASAChain
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

	timeoutStr := "0"
	if identityTimeout := icfg.SessionTimeout(); identityTimeout > 0 {
		timeoutStr = identityTimeout.String()
	}
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
		SSHEnabled:           sshInfo.Enabled,
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
	if !sshInfo.Enabled || sshInfo.Port <= 0 {
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

func (s Service) UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error {
	if req.Key == adminproto.AdminSettingSSHListenAddress || req.Key == adminproto.AdminSettingEndpointAdvertiseURL {
		return protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("unknown or read-only setting: %s", req.Key))
	}
	return s.Deps.WithStoreMutation(func() error {
		return s.updateAdminSettingLocked(req)
	})
}

func (s Service) updateAdminSettingLocked(req adminproto.UpdateAdminSettingRequest) error {
	ir := s.Runtime
	icfg := ir.Config()
	unsaved := icfg.IsUnsaved(req.Key)

	// The new value is a candidate until it is published. A restrictive one
	// (see restricts) is published before the save, so it is in effect for
	// as long as the save takes and stays in effect if the save fails. Any
	// other value (theme, passphrase_timeout, the value already saved) is
	// published only once the save returns, so no reader, a signing request
	// included, ever sees a permissive value that was not saved, and a failed
	// save of an unchanged value reports nothing in effect that a restart
	// would undo.
	var saveValue interface{}
	var publish func()
	var restrictive bool

	switch req.Key {
	case adminproto.AdminSettingRequireContained:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		contained, cosigner := icfg.GenerationRequirements()
		saveValue, publish = v, func() { icfg.SetGenerationRequirements(v, cosigner) }
		restrictive = restricts(true, v, contained, unsaved)
	case adminproto.AdminSettingRequireCosigner:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		contained, cosigner := icfg.GenerationRequirements()
		saveValue, publish = v, func() { icfg.SetGenerationRequirements(contained, v) }
		restrictive = restricts(true, v, cosigner, unsaved)
	case adminproto.AdminSettingUserAutoApprove:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		saveValue, publish = v, func() { icfg.SetUserAutoApprove(v) }
		restrictive = restricts(false, v, icfg.UserAutoApprove(), unsaved)
	case adminproto.AdminSettingLockOnDisconnect:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		if passphraseMethod := s.Runtime.UnlockMethod(); passphraseMethod != unlockconfig.MethodNone && v {
			return fmt.Errorf("cannot enable lock_on_disconnect in headless mode (passphrase method: %s)", passphraseMethod)
		}
		saveValue, publish = v, func() { icfg.SetLockOnDisconnect(v) }
		restrictive = restricts(true, v, icfg.LockOnDisconnect(), unsaved)
	case adminproto.AdminSettingPassphraseTimeout:
		// Only the admin client enforces the timeout, so publishing it early
		// would change nothing in the signer: it is never restrictive.
		duration, err := serverconfig.ParsePassphraseTimeout(req.Value)
		if err != nil {
			return err
		}
		if passphraseMethod := s.Runtime.UnlockMethod(); passphraseMethod != unlockconfig.MethodNone && duration > 0 {
			return fmt.Errorf("cannot set passphrase_timeout in headless mode (passphrase method: %s)", passphraseMethod)
		}
		saveValue, publish = req.Value, func() { icfg.SetSessionTimeout(duration) }
	case adminproto.AdminSettingTheme:
		v := strings.ToLower(req.Value)
		if v != "auto" && v != "dark" && v != "light" {
			return fmt.Errorf("invalid theme %q (must be auto, dark, or light)", req.Value)
		}
		saveValue, publish = v, func() { icfg.SetTheme(v) }
	default:
		return protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("unknown or read-only setting: %s", req.Key))
	}

	if restrictive {
		// In effect and ahead of the file until the save puts the new file
		// in place, which clears it below: a save that hangs leaves it
		// reported unsaved.
		publish()
		icfg.SetUnsaved(req.Key, true)
	}
	// The save rewrites only this key of the product runtime config: an
	// edit to another key of the file made while the signer runs stays in
	// the file and takes effect at the next start. The process-global
	// config.yaml is never written.
	saveErr := productruntime.SaveStoredSetting(s.Deps.DataDir(), req.Key, saveValue)
	switch {
	case saveErr == nil || errors.Is(saveErr, fsutil.ErrPublishedNotDurable):
		// The new file is in place and is what the next start loads, so
		// memory follows it (a restrictive value already does) and is no
		// longer ahead of it. The directory flush after the rename is best
		// effort: its failure does not say the change missed the disk, so
		// it is a success, logged because it points at a failing disk.
		publish()
		icfg.SetUnsaved(req.Key, false)
		if saveErr != nil {
			s.Deps.Warnf("setting %s saved, but its directory flush failed: %v", req.Key, saveErr)
		}
		return nil
	case restrictive:
		// The old file is still in place. Memory keeps the restrictive value
		// rather than go back to the permissive one it replaced, and the
		// signer reports the setting unsaved until a save of it succeeds.
		return protocol.WithCode(protocol.ResultCodeAppliedNotSaved,
			&adminproto.SettingSaveError{Key: req.Key, Value: fmt.Sprint(saveValue), InEffect: true, Err: saveErr})
	default:
		return &adminproto.SettingSaveError{Key: req.Key, Value: fmt.Sprint(saveValue), Err: saveErr}
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
