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
	// ASAChain reads assets for the ASA set; nil leaves the set read-only.
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

	requireContained, requireCosigner := icfg.GenerationRequirements()
	return adminproto.AdminSettings{
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

	// The new value is a candidate until it is saved: publish makes it live
	// only afterward, so no reader (a signing request included) ever sees a
	// value the file does not hold.
	var saveValue interface{}
	var publish func()
	icfg := ir.Config()

	switch req.Key {
	case adminproto.AdminSettingRequireContained:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		_, cosigner := icfg.GenerationRequirements()
		saveValue, publish = v, func() { icfg.SetGenerationRequirements(v, cosigner) }
	case adminproto.AdminSettingRequireCosigner:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		contained, _ := icfg.GenerationRequirements()
		saveValue, publish = v, func() { icfg.SetGenerationRequirements(contained, v) }
	case adminproto.AdminSettingUserAutoApprove:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		saveValue, publish = v, func() { icfg.SetUserAutoApprove(v) }
	case adminproto.AdminSettingLockOnDisconnect:
		v, err := parseBoolSetting(req)
		if err != nil {
			return err
		}
		if passphraseMethod := s.detectPassphraseMethod(); passphraseMethod != "none" && v {
			return fmt.Errorf("cannot enable lock_on_disconnect in headless mode (passphrase method: %s)", passphraseMethod)
		}
		saveValue, publish = v, func() { icfg.SetLockOnDisconnect(v) }
	case adminproto.AdminSettingPassphraseTimeout:
		duration, err := serverconfig.ParsePassphraseTimeout(req.Value)
		if err != nil {
			return err
		}
		if passphraseMethod := s.detectPassphraseMethod(); passphraseMethod != "none" && duration > 0 {
			return fmt.Errorf("cannot set passphrase_timeout in headless mode (passphrase method: %s)", passphraseMethod)
		}
		saveValue, publish = req.Value, func() { icfg.SetSessionTimeout(duration) }
	case adminproto.AdminSettingTheme:
		v := strings.ToLower(req.Value)
		if v != "auto" && v != "dark" && v != "light" {
			return fmt.Errorf("invalid theme %q (must be auto, dark, or light)", req.Value)
		}
		saveValue, publish = v, func() { s.Deps.SetTheme(v) }
	default:
		return protocol.WithCode(protocol.ErrCodeInvalidRequest, fmt.Errorf("unknown or read-only setting: %s", req.Key))
	}

	mut := storemut.New(s.Deps.KeyPaths())
	var saveErr error
	if req.Key == adminproto.AdminSettingTheme {
		saveErr = mut.SaveServerSetting(s.Deps.DataDir(), req.Key, saveValue)
	} else {
		saveErr = mut.SaveRuntimeSetting(s.Deps.DataDir(), req.Key, saveValue)
	}
	switch {
	case saveErr == nil:
		publish()
		return nil
	case errors.Is(saveErr, fsutil.ErrPublishedNotDurable):
		// The new file is in place and is what the next start loads, so
		// memory follows it rather than keep a value the file no longer holds.
		publish()
		return fmt.Errorf("%s is set to %v and in effect, but its durability is not confirmed: %w", req.Key, saveValue, saveErr)
	default:
		return fmt.Errorf("failed to save config.yaml; %s is unchanged: %w", req.Key, saveErr)
	}
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
