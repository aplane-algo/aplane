// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"bytes"
	"errors"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
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

// SetTheme updates the process config too, as the signer's does, so the
// external-change check compares the file with the live theme.
func (d *fakeDeps) SetTheme(v string) {
	d.theme = v
	d.config.Theme = v
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

func TestGenerationRequirementsAreSavedAndLoaded(t *testing.T) {
	dataRoot := t.TempDir()
	for _, key := range []string{adminproto.AdminSettingRequireContained, adminproto.AdminSettingRequireCosigner} {
		if err := productruntime.SaveStoredSetting(dataRoot, key, true); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := productruntime.LoadStoredConfig(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := stored.Apply(productruntime.ConfigDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if !effective.RequireContained || !effective.RequireCosigner {
		t.Fatalf("effective config = %+v", effective)
	}
}

func TestGenerationRequirementSettingsTakeEffectAndPersist(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		key                     string
		wantAdmin, wantCosigner bool
	}{
		{adminproto.AdminSettingRequireContained, true, false},
		{adminproto.AdminSettingRequireCosigner, true, true},
	} {
		if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: test.key, Value: "true"}); err != nil {
			t.Fatalf("UpdateAdminSetting(%s) error = %v", test.key, err)
		}
		admin, cosigner := ir.Config().GenerationRequirements()
		if admin != test.wantAdmin || cosigner != test.wantCosigner {
			t.Fatalf("%s: requirements = %v, %v", test.key, admin, cosigner)
		}
	}
	stored, err := productruntime.LoadStoredConfig(deps.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := stored.Apply(productruntime.ConfigDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if !effective.RequireContained || !effective.RequireCosigner {
		t.Fatalf("persisted config = %+v", effective)
	}
	ir.Config().SetGenerationRequirements(true, false)
	if settings := svc.BuildAdminSettings(); !settings.RequireContained || settings.RequireCosigner {
		t.Fatalf("reported settings = %+v", settings)
	}
}

func TestGenerationRequirementIsNotAppliedWhenItCannotBeSaved(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	// A directory where the runtime config belongs makes the save fail.
	if err := os.MkdirAll(productruntime.ConfigPath(deps.dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingRequireContained, Value: "true"})
	if err == nil {
		t.Fatal("the save did not fail")
	}
	if admin, _ := ir.Config().GenerationRequirements(); admin {
		t.Fatal("a requirement stayed active after it could not be saved")
	}
}

// writeRootConfig gives the service the config.yaml its external-change
// check reads.
func writeRootConfig(t *testing.T, deps *fakeDeps) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}
}

// failDurableWriteAt makes the durable write step op on path fail.
func failDurableWriteAt(t *testing.T, op fsutil.HookOp, path string) {
	t.Helper()
	fsutil.TestHook = func(got fsutil.HookOp, gotPath string) error {
		if got == op && gotPath == path {
			return errors.New("injected " + string(got) + " failure")
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
}

var boolSettingKeys = []string{
	adminproto.AdminSettingRequireContained,
	adminproto.AdminSettingRequireCosigner,
	adminproto.AdminSettingUserAutoApprove,
	adminproto.AdminSettingLockOnDisconnect,
}

// A boolean setting accepts exactly "true" or "false". Anything else once
// read as false, so a typo turned a setting off.
func TestUpdateAdminSettingRefusesNonCanonicalBooleans(t *testing.T) {
	for _, key := range boolSettingKeys {
		for _, value := range []string{"", "True", "1", "yes"} {
			t.Run(key+"="+strconv.Quote(value), func(t *testing.T) {
				svc, _, deps := setupAdminService(t)
				writeRootConfig(t, deps)
				// Every setting on, so a value read as false would show.
				for _, k := range boolSettingKeys {
					if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: k, Value: "true"}); err != nil {
						t.Fatalf("UpdateAdminSetting(%s=true) error = %v", k, err)
					}
				}
				before := svc.BuildAdminSettings()
				diskBefore, err := os.ReadFile(productruntime.ConfigPath(deps.dataDir))
				if err != nil {
					t.Fatal(err)
				}

				err = svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: key, Value: value})
				if err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
					t.Fatalf("UpdateAdminSetting(%s=%q) error = %v, want an invalid_request refusal", key, value, err)
				}
				if after := svc.BuildAdminSettings(); after != before {
					t.Fatalf("settings changed by a refused value:\nbefore %+v\nafter  %+v", before, after)
				}
				diskAfter, err := os.ReadFile(productruntime.ConfigPath(deps.dataDir))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(diskAfter, diskBefore) {
					t.Fatalf("runtime config changed by a refused value:\nbefore %s\nafter  %s", diskBefore, diskAfter)
				}
			})
		}
	}
}

// saveFailureCase is one setting change whose save is made to fail.
type saveFailureCase struct {
	name     string
	key      string
	from, to string
	// target is the file the setting is saved in.
	target func(dataDir string) string
	live   func(svc Service, ir *productruntime.Runtime) string
	stored func(t *testing.T, dataDir string) string
}

func saveFailureCases() []saveFailureCase {
	runtimeTarget := productruntime.ConfigPath
	autoApproveLive := func(_ Service, ir *productruntime.Runtime) string {
		return strconv.FormatBool(ir.Config().UserAutoApprove())
	}
	autoApproveStored := func(t *testing.T, dataDir string) string {
		t.Helper()
		stored, err := productruntime.LoadStoredConfig(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if stored.UserAutoApprove == nil {
			return "unset"
		}
		return strconv.FormatBool(*stored.UserAutoApprove)
	}
	return []saveFailureCase{
		{
			name: "enable auto-approve", key: adminproto.AdminSettingUserAutoApprove, from: "false", to: "true",
			target: runtimeTarget, live: autoApproveLive, stored: autoApproveStored,
		},
		{
			name: "disable auto-approve", key: adminproto.AdminSettingUserAutoApprove, from: "true", to: "false",
			target: runtimeTarget, live: autoApproveLive, stored: autoApproveStored,
		},
		{
			name: "theme", key: adminproto.AdminSettingTheme, from: "auto", to: "dark",
			target: func(dataDir string) string { return filepath.Join(dataDir, "config.yaml") },
			live:   func(svc Service, _ *productruntime.Runtime) string { return svc.Deps.Theme() },
			stored: func(t *testing.T, dataDir string) string {
				t.Helper()
				cfg, err := serverconfig.LoadServerConfig(dataDir)
				if err != nil {
					t.Fatal(err)
				}
				return cfg.Theme
			},
		},
	}
}

// startSaveFailureCase sets tc.from, both live and saved.
func startSaveFailureCase(t *testing.T, tc saveFailureCase) (Service, *productruntime.Runtime, *fakeDeps) {
	t.Helper()
	svc, ir, deps := setupAdminService(t)
	writeRootConfig(t, deps)
	if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: tc.key, Value: tc.from}); err != nil {
		t.Fatalf("UpdateAdminSetting(%s=%s) error = %v", tc.key, tc.from, err)
	}
	if live, stored := tc.live(svc, ir), tc.stored(t, deps.dataDir); live != tc.from || stored != tc.from {
		t.Fatalf("start state: live %s, saved %s; want %s", live, stored, tc.from)
	}
	return svc, ir, deps
}

// A save that fails before its rename leaves the old file in place, so the
// setting stays what it was, live and saved.
func TestUpdateAdminSettingFailureBeforeRenameChangesNothing(t *testing.T) {
	for _, tc := range saveFailureCases() {
		for _, op := range []fsutil.HookOp{fsutil.OpFileSync, fsutil.OpRename} {
			t.Run(tc.name+"/"+string(op), func(t *testing.T) {
				svc, ir, deps := startSaveFailureCase(t, tc)
				failDurableWriteAt(t, op, tc.target(deps.dataDir))

				err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: tc.key, Value: tc.to})
				fsutil.TestHook = nil
				if err == nil || errors.Is(err, fsutil.ErrPublishedNotDurable) || !strings.Contains(err.Error(), "unchanged") {
					t.Fatalf("UpdateAdminSetting error = %v, want the save failure with the setting unchanged", err)
				}
				if live, stored := tc.live(svc, ir), tc.stored(t, deps.dataDir); live != tc.from || stored != tc.from {
					t.Fatalf("after the failed save: live %s, saved %s; want both %s", live, stored, tc.from)
				}
			})
		}
	}
}

// A save that fails after its rename (the directory sync) has put the new
// file in place, which is what the next start loads. The new value then takes
// effect, the error says its durability is unconfirmed, and memory never
// goes back to a value the file no longer holds.
func TestUpdateAdminSettingFailureAfterRenamePublishesTheSavedValue(t *testing.T) {
	for _, tc := range saveFailureCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc, ir, deps := startSaveFailureCase(t, tc)
			failDurableWriteAt(t, fsutil.OpDirSync, filepath.Dir(tc.target(deps.dataDir)))

			err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: tc.key, Value: tc.to})
			fsutil.TestHook = nil
			if !errors.Is(err, fsutil.ErrPublishedNotDurable) ||
				!strings.Contains(err.Error(), "in effect") || !strings.Contains(err.Error(), "durability is not confirmed") {
				t.Fatalf("UpdateAdminSetting error = %v, want in effect with durability unconfirmed", err)
			}
			if live, stored := tc.live(svc, ir), tc.stored(t, deps.dataDir); live != tc.to || stored != tc.to {
				t.Fatalf("after the unsynced save: live %s, saved %s; want both %s", live, stored, tc.to)
			}
			// Memory and file agree, so the next change is not refused as an
			// external edit.
			if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: tc.key, Value: tc.from}); err != nil {
				t.Fatalf("next UpdateAdminSetting error = %v", err)
			}
			if live, stored := tc.live(svc, ir), tc.stored(t, deps.dataDir); live != tc.from || stored != tc.from {
				t.Fatalf("after the next save: live %s, saved %s; want both %s", live, stored, tc.from)
			}
		})
	}
}
