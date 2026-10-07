// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type fakeDeps struct {
	dataDir  string
	config   *serverconfig.ServerConfig
	keyPaths storepaths.Paths
	theme    string
	sshInfo  SSHInfo
	mu       sync.Mutex

	processMutationCalls  int
	identityMutationCalls int
}

func (d *fakeDeps) DataDir() string {
	return d.dataDir
}

func (d *fakeDeps) Config() *serverconfig.ServerConfig {
	return d.config
}

func (d *fakeDeps) KeyPaths() storepaths.Paths {
	return d.keyPaths
}

func (d *fakeDeps) Theme() string {
	return d.theme
}

func (d *fakeDeps) SetTheme(v string) {
	d.theme = v
}

func (d *fakeDeps) SSHInfo() SSHInfo {
	return d.sshInfo
}

func (d *fakeDeps) WithProcessConfigMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.processMutationCalls++
	return fn()
}

func (d *fakeDeps) WithStoreMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.identityMutationCalls++
	return fn()
}

func setupAdminService(t *testing.T) (Service, *productruntime.Runtime, *fakeDeps) {
	return setupAdminServiceWithRole(t, noderole.RoleSigner)
}

func setupAdminServiceWithRole(t *testing.T, role noderole.Role) (Service, *productruntime.Runtime, *fakeDeps) {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	keyring, active := genstoretest.MintFirstAtomic(t, keyPaths, []byte("admin-policy-test-passphrase"))
	keyring.Zero()
	keyPaths = genstoretest.BindActive(t, keyPaths, active)

	cfg := serverconfig.DefaultServerConfig()
	cfg.Theme = "auto"
	deps := &fakeDeps{
		dataDir:  tmpDir,
		config:   &cfg,
		keyPaths: keyPaths,
		theme:    cfg.Theme,
	}
	keyStore := keystore.NewAtomicFileKeyStoreForPaths(keyPaths)
	ir := productruntime.New(productruntime.Config{
		KeyStore: keyStore,
		KeyPaths: keyPaths,
		NodeRole: role,
	})
	return Service{Deps: deps, Runtime: ir}, ir, deps
}

func TestDetectPassphraseMethod(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{name: "empty argv returns none", argv: nil, want: "none"},
		{name: "appass-file bare", argv: []string{"appass-file", "/tmp/secret"}, want: "passfile"},
		{name: "appass-file absolute", argv: []string{"/usr/local/bin/appass-file", "/tmp/secret"}, want: "passfile"},
		{name: "appass-systemd-creds bare", argv: []string{"appass-systemd-creds"}, want: "systemd-creds"},
		{name: "appass-systemd-creds absolute", argv: []string{"/usr/bin/appass-systemd-creds"}, want: "systemd-creds"},
		{name: "custom command", argv: []string{"/usr/bin/my-unlock-helper"}, want: "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectPassphraseMethod(tt.argv)
			if got != tt.want {
				t.Errorf("DetectPassphraseMethod(%v) = %q, want %q", tt.argv, got, tt.want)
			}
		})
	}
}

func TestServiceDetectPassphraseMethodReadsUnlockYAML(t *testing.T) {
	svc, _, deps := setupAdminService(t)

	got := svc.detectPassphraseMethod()
	if got != "none" {
		t.Fatalf("before unlock.yaml: got %q, want %q", got, "none")
	}

	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(deps.dataDir, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	got = svc.detectPassphraseMethod()
	if got != "passfile" {
		t.Fatalf("after unlock.yaml with appass-file: got %q, want %q", got, "passfile")
	}
}

func TestServiceDetectPassphraseMethodFallsBackToGlobalConfig(t *testing.T) {
	svc, _, deps := setupAdminService(t)

	deps.config.PassphraseCommandArgv = []string{"/usr/bin/appass-systemd-creds"}

	got := svc.detectPassphraseMethod()
	if got != "systemd-creds" {
		t.Fatalf("global fallback: got %q, want %q", got, "systemd-creds")
	}
}

func TestServiceDetectPassphraseMethodProductStoreOverridesGlobal(t *testing.T) {
	svc, _, deps := setupAdminService(t)

	deps.config.PassphraseCommandArgv = []string{"/usr/bin/appass-systemd-creds"}
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(deps.dataDir, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	got := svc.detectPassphraseMethod()
	if got != "passfile" {
		t.Fatalf("product-store should override global: got %q, want %q", got, "passfile")
	}
}

func TestServiceDetectPassphraseMethodMalformedUnlockYAMLFallsBackToGlobal(t *testing.T) {
	svc, _, deps := setupAdminService(t)
	deps.config.PassphraseCommandArgv = []string{"/usr/bin/appass-systemd-creds"}

	unlockPath := unlockconfig.UnlockConfigPath(deps.dataDir)
	if err := os.MkdirAll(filepath.Dir(unlockPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(unlock config dir): %v", err)
	}
	if err := os.WriteFile(unlockPath, []byte("passphrase_command: [\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(unlock.yaml): %v", err)
	}

	if got := svc.detectPassphraseMethod(); got != "systemd-creds" {
		t.Fatalf("malformed unlock.yaml fallback = %q, want systemd-creds", got)
	}
}

func TestBuildAdminSettingsEndpointDisplayURL(t *testing.T) {
	oldDetect := detectPrimaryOutboundIPv4
	t.Cleanup(func() {
		detectPrimaryOutboundIPv4 = oldDetect
	})

	tests := []struct {
		name          string
		listenAddress string
		advertiseURL  string
		detectedIP    string
		want          string
	}{
		{
			name:          "configured advertise url wins",
			listenAddress: "0.0.0.0",
			advertiseURL:  "ssh://signer.example:1127",
			detectedIP:    "192.168.1.42",
			want:          "ssh://signer.example:1127",
		},
		{
			name:          "concrete listen address",
			listenAddress: "192.0.2.10",
			want:          "ssh://192.0.2.10:64804",
		},
		{
			name:          "wildcard bind uses detected primary IPv4",
			listenAddress: "0.0.0.0",
			detectedIP:    "192.168.1.42",
			want:          "ssh://192.168.1.42:64804",
		},
		{
			name:          "wildcard bind falls back to loopback",
			listenAddress: "0.0.0.0",
			want:          "ssh://127.0.0.1:64804",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectPrimaryOutboundIPv4 = func() string {
				return tt.detectedIP
			}
			svc, _, deps := setupAdminService(t)
			deps.config.Endpoint.SSH.ListenAddress = tt.listenAddress
			deps.config.Endpoint.AdvertiseURL = tt.advertiseURL
			deps.sshInfo = SSHInfo{Enabled: true, Port: 64804}

			settings := svc.BuildAdminSettings()
			if settings.EndpointAdvertiseURL != tt.advertiseURL {
				t.Fatalf("EndpointAdvertiseURL = %q, want %q", settings.EndpointAdvertiseURL, tt.advertiseURL)
			}
			if settings.EndpointDisplayURL != tt.want {
				t.Fatalf("EndpointDisplayURL = %q, want %q", settings.EndpointDisplayURL, tt.want)
			}
		})
	}
}

func TestUpdateAdminSettingUsesExpectedMutationLock(t *testing.T) {
	t.Run("theme uses process config mutation lock", func(t *testing.T) {
		svc, _, deps := setupAdminService(t)
		if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
			t.Fatal(err)
		}

		if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingTheme, Value: "dark"}); err != nil {
			t.Fatalf("UpdateAdminSetting(theme) error = %v", err)
		}
		if deps.processMutationCalls != 1 {
			t.Fatalf("processMutationCalls = %d, want 1", deps.processMutationCalls)
		}
		if deps.identityMutationCalls != 0 {
			t.Fatalf("identityMutationCalls = %d, want 0", deps.identityMutationCalls)
		}
	})

	t.Run("identity setting uses store mutation lock", func(t *testing.T) {
		svc, _, deps := setupAdminService(t)
		if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
			t.Fatal(err)
		}

		if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingUserAutoApprove, Value: "true"}); err != nil {
			t.Fatalf("UpdateAdminSetting(user_auto_approve) error = %v", err)
		}
		if deps.processMutationCalls != 0 {
			t.Fatalf("processMutationCalls = %d, want 0", deps.processMutationCalls)
		}
		if deps.identityMutationCalls != 1 {
			t.Fatalf("identityMutationCalls = %d, want 1", deps.identityMutationCalls)
		}
	})
}

func TestUpdateAdminSettingRejectsInfrastructureNetworkSettings(t *testing.T) {
	tests := []struct {
		key   string
		value string
	}{
		{key: adminproto.AdminSettingSSHListenAddress, value: "0.0.0.0"},
		{key: adminproto.AdminSettingEndpointAdvertiseURL, value: "ssh://signer.example:1127"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			svc, _, deps := setupAdminService(t)
			if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
				t.Fatal(err)
			}

			err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
				Key:   tt.key,
				Value: tt.value,
			})
			if err == nil {
				t.Fatalf("UpdateAdminSetting(%s) error = nil, want read-only rejection", tt.key)
			}
			if !strings.Contains(err.Error(), "unknown or read-only setting") {
				t.Fatalf("UpdateAdminSetting(%s) error = %v, want read-only rejection", tt.key, err)
			}
			if deps.processMutationCalls != 0 {
				t.Fatalf("processMutationCalls = %d, want 0", deps.processMutationCalls)
			}
			if deps.identityMutationCalls != 0 {
				t.Fatalf("identityMutationCalls = %d, want 0", deps.identityMutationCalls)
			}
			if deps.config.Endpoint.SSH.ListenAddress != apconfig.DefaultSSHListenAddress {
				t.Fatalf("Endpoint.SSH.ListenAddress = %q, want unchanged default", deps.config.Endpoint.SSH.ListenAddress)
			}
			if deps.config.Endpoint.AdvertiseURL != "" {
				t.Fatalf("Endpoint.AdvertiseURL = %q, want unchanged empty", deps.config.Endpoint.AdvertiseURL)
			}
		})
	}
}
