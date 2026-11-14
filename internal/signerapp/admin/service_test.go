// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"bytes"
	"errors"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/fsutil/fsutiltest"
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
		writeRootConfig(t, deps)

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
		writeRootConfig(t, deps)

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
			writeRootConfig(t, deps)

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
	writeRootConfig(t, deps)
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

// A requirement turned on is restrictive, so it is in effect even when it
// cannot be saved; one turned off is not applied unless it is saved.
func TestGenerationRequirementCannotBeSaved(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	writeRootConfig(t, deps)
	ir.Config().SetGenerationRequirements(false, true)
	// A directory where the runtime config belongs makes the save fail.
	if err := os.MkdirAll(productruntime.ConfigPath(deps.dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingRequireContained, Value: "true"})
	if protocol.CodeForError(err) != protocol.ResultCodeAppliedNotSaved {
		t.Fatalf("turning a requirement on: error = %v, want %s", err, protocol.ResultCodeAppliedNotSaved)
	}
	if contained, _ := ir.Config().GenerationRequirements(); !contained {
		t.Fatal("a requirement turned on is not in effect after its save failed")
	}
	err = svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingRequireCosigner, Value: "false"})
	if err == nil || protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved {
		t.Fatalf("turning a requirement off: error = %v, want a plain save failure", err)
	}
	if _, cosigner := ir.Config().GenerationRequirements(); !cosigner {
		t.Fatal("a requirement turned off was applied after its save failed")
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
				if after := svc.BuildAdminSettings(); !reflect.DeepEqual(after, before) {
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

// settingChange is one change of a writable setting from a saved starting
// value. restrictive is its direction: a restrictive change is in effect from
// before its save until whatever the save does; any other change (theme
// included) takes effect only once its file has replaced the old one.
type settingChange struct {
	key, from, to string
	restrictive   bool
}

func (c settingChange) name() string {
	return c.key + "=" + c.from + "->" + c.to
}

// settingChanges is every writable setting in each direction. Only the three
// boolean settings the signer enforces are ever restrictive: only the admin
// client enforces passphrase_timeout, so a shorter one is not.
func settingChanges() []settingChange {
	return []settingChange{
		{adminproto.AdminSettingUserAutoApprove, "true", "false", true},
		{adminproto.AdminSettingUserAutoApprove, "false", "true", false},
		{adminproto.AdminSettingRequireContained, "false", "true", true},
		{adminproto.AdminSettingRequireContained, "true", "false", false},
		{adminproto.AdminSettingRequireCosigner, "false", "true", true},
		{adminproto.AdminSettingRequireCosigner, "true", "false", false},
		{adminproto.AdminSettingLockOnDisconnect, "false", "true", true},
		{adminproto.AdminSettingLockOnDisconnect, "true", "false", false},
		{adminproto.AdminSettingPassphraseTimeout, "0", "15m", false},
		{adminproto.AdminSettingPassphraseTimeout, "30m", "15m", false},
		{adminproto.AdminSettingPassphraseTimeout, "15m", "30m", false},
		{adminproto.AdminSettingPassphraseTimeout, "15m", "0", false},
		{adminproto.AdminSettingTheme, "auto", "dark", false},
	}
}

// settingTarget is the file key is saved in.
func settingTarget(dataDir, key string) string {
	if key == adminproto.AdminSettingTheme {
		return filepath.Join(dataDir, "config.yaml")
	}
	return productruntime.ConfigPath(dataDir)
}

// normalSetting writes value as liveSetting and storedSetting report it.
func normalSetting(t *testing.T, key, value string) string {
	t.Helper()
	if key != adminproto.AdminSettingPassphraseTimeout {
		return value
	}
	d, err := serverconfig.ParsePassphraseTimeout(value)
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

// liveSetting is the value readers see now.
func liveSetting(t *testing.T, svc Service, ir *productruntime.Runtime, key string) string {
	t.Helper()
	cfg := ir.Config()
	contained, cosigner := cfg.GenerationRequirements()
	switch key {
	case adminproto.AdminSettingUserAutoApprove:
		return strconv.FormatBool(cfg.UserAutoApprove())
	case adminproto.AdminSettingRequireContained:
		return strconv.FormatBool(contained)
	case adminproto.AdminSettingRequireCosigner:
		return strconv.FormatBool(cosigner)
	case adminproto.AdminSettingLockOnDisconnect:
		return strconv.FormatBool(cfg.LockOnDisconnect())
	case adminproto.AdminSettingPassphraseTimeout:
		return cfg.SessionTimeout().String()
	case adminproto.AdminSettingTheme:
		return svc.Deps.Theme()
	}
	t.Fatalf("no live reader for %s", key)
	return ""
}

// storedSetting is the value the next start loads.
func storedSetting(t *testing.T, dataDir, key string) string {
	t.Helper()
	if key == adminproto.AdminSettingTheme {
		cfg, err := serverconfig.LoadServerConfig(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Theme
	}
	stored, err := productruntime.LoadStoredConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	b := func(v *bool) string {
		if v == nil {
			return "unset"
		}
		return strconv.FormatBool(*v)
	}
	switch key {
	case adminproto.AdminSettingUserAutoApprove:
		return b(stored.UserAutoApprove)
	case adminproto.AdminSettingRequireContained:
		return b(stored.RequireContained)
	case adminproto.AdminSettingRequireCosigner:
		return b(stored.RequireCosigner)
	case adminproto.AdminSettingLockOnDisconnect:
		return b(stored.LockOnDisconnect)
	case adminproto.AdminSettingPassphraseTimeout:
		return normalSetting(t, key, stored.PassphraseTimeout)
	}
	t.Fatalf("no stored reader for %s", key)
	return ""
}

// startSettingChange sets c.from, both live and saved.
func startSettingChange(t *testing.T, c settingChange) (Service, *productruntime.Runtime, *fakeDeps) {
	t.Helper()
	svc, ir, deps := setupAdminService(t)
	writeRootConfig(t, deps)
	if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.from}); err != nil {
		t.Fatalf("UpdateAdminSetting(%s=%s) error = %v", c.key, c.from, err)
	}
	requireSetting(t, svc, ir, deps, c.key, c.from, c.from, "start state")
	return svc, ir, deps
}

func requireSetting(t *testing.T, svc Service, ir *productruntime.Runtime, deps *fakeDeps, key, live, stored, when string) {
	t.Helper()
	wantLive, wantStored := normalSetting(t, key, live), normalSetting(t, key, stored)
	if gotLive, gotStored := liveSetting(t, svc, ir, key), storedSetting(t, deps.dataDir, key); gotLive != wantLive || gotStored != wantStored {
		t.Fatalf("%s: live %s, saved %s; want live %s, saved %s", when, gotLive, gotStored, wantLive, wantStored)
	}
}

// A restrictive change is in effect while its save runs; a permissive one is
// not in effect until its file has replaced the old one. Either way the
// completed save leaves the new value live and saved.
func TestSettingDirectionDecidesWhenAChangeTakesEffect(t *testing.T) {
	for _, c := range settingChanges() {
		t.Run(c.name(), func(t *testing.T) {
			svc, ir, deps := startSettingChange(t, c)
			held := fsutiltest.Hold(t, fsutil.OpRename, settingTarget(deps.dataDir, c.key), func() error {
				return svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			})
			during := c.from
			if c.restrictive {
				during = c.to
			}
			if got, want := liveSetting(t, svc, ir, c.key), normalSetting(t, c.key, during); got != want {
				t.Fatalf("live during the save = %s, want %s (restrictive %v)", got, want, c.restrictive)
			}
			if err := held.Finish(nil); err != nil {
				t.Fatalf("UpdateAdminSetting error = %v", err)
			}
			requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the save")
		})
	}
}

// A save that fails before its rename leaves the old file in place, so a
// restart loads the old value. A permissive change is then not applied. A
// restrictive one stays in effect, coded applied_not_saved with an error
// that says so; memory never goes back to the permissive value it replaced.
// The external-edit check compares root config.yaml with the startup
// config, not memory with the identity's file, so the next update is not
// refused.
func TestUpdateAdminSettingFailureBeforeRename(t *testing.T) {
	for _, c := range settingChanges() {
		for _, op := range []fsutil.HookOp{fsutil.OpFileSync, fsutil.OpRename} {
			t.Run(c.name()+"/"+string(op), func(t *testing.T) {
				svc, ir, deps := startSettingChange(t, c)
				failDurableWriteAt(t, op, settingTarget(deps.dataDir, c.key))

				err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
				fsutil.TestHook = nil
				if err == nil || errors.Is(err, fsutil.ErrPublishedNotDurable) || protocol.CodeForError(err) == protocol.ResultCodeAppliedNotDurable {
					t.Fatalf("UpdateAdminSetting error = %v, want a save failure before the rename", err)
				}
				if c.restrictive {
					if protocol.CodeForError(err) != protocol.ResultCodeAppliedNotSaved ||
						!strings.Contains(err.Error(), "in effect now, but it was not saved, so a restart loads the old value") {
						t.Fatalf("UpdateAdminSetting error = %v (code %q), want %s: in effect, not saved", err, protocol.CodeForError(err), protocol.ResultCodeAppliedNotSaved)
					}
					requireSetting(t, svc, ir, deps, c.key, c.to, c.from, "after the failed save")
				} else {
					if protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved || !strings.Contains(err.Error(), "unchanged") {
						t.Fatalf("UpdateAdminSetting error = %v (code %q), want the save failure with the setting unchanged", err, protocol.CodeForError(err))
					}
					requireSetting(t, svc, ir, deps, c.key, c.from, c.from, "after the failed save")
				}
				if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to}); err != nil {
					t.Fatalf("next UpdateAdminSetting error = %v", err)
				}
				requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the next save")
			})
		}
	}
}

// A request for the value already in effect is not restrictive, whatever the
// value: it takes the save-first path, so a failed save answers the plain
// "unchanged" failure. It once answered applied_not_saved ("a restart loads
// the old value") and was audited, although nothing changed.
func TestUnchangedValueWhoseSaveFailsReportsNothingInEffect(t *testing.T) {
	for _, c := range settingChanges() {
		if !c.restrictive {
			continue
		}
		t.Run(c.key+"="+c.to, func(t *testing.T) {
			same := settingChange{key: c.key, from: c.to, to: c.to}
			svc, ir, deps := startSettingChange(t, same)
			failDurableWriteAt(t, fsutil.OpRename, settingTarget(deps.dataDir, c.key))

			err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			fsutil.TestHook = nil
			if err == nil || protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved || !strings.Contains(err.Error(), "unchanged") {
				t.Fatalf("UpdateAdminSetting error = %v (code %q), want the plain unchanged failure", err, protocol.CodeForError(err))
			}
			requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the failed save")
		})
	}
}

// A save that fails after its rename (the directory sync) has put the new
// file in place, which is what the next start loads. The new value then takes
// effect, in either direction, the error says its durability is unconfirmed,
// and memory never goes back to a value the file no longer holds.
func TestUpdateAdminSettingFailureAfterRenamePublishesTheSavedValue(t *testing.T) {
	for _, c := range settingChanges() {
		t.Run(c.name(), func(t *testing.T) {
			svc, ir, deps := startSettingChange(t, c)
			failDurableWriteAt(t, fsutil.OpDirSync, filepath.Dir(settingTarget(deps.dataDir, c.key)))

			err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			fsutil.TestHook = nil
			if !errors.Is(err, fsutil.ErrPublishedNotDurable) || protocol.CodeForError(err) != protocol.ResultCodeAppliedNotDurable ||
				!strings.Contains(err.Error(), "in effect") || !strings.Contains(err.Error(), "durability is not confirmed") {
				t.Fatalf("UpdateAdminSetting error = %v (code %q), want %s: in effect with durability unconfirmed", err, protocol.CodeForError(err), protocol.ResultCodeAppliedNotDurable)
			}
			requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the unsynced save")
			// Memory and file agree, so the next change is not refused as an
			// external edit.
			if err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.from}); err != nil {
				t.Fatalf("next UpdateAdminSetting error = %v", err)
			}
			requireSetting(t, svc, ir, deps, c.key, c.from, c.from, "after the next save")
		})
	}
}

// unsavedSettings is what admin_settings reports as in effect but not saved.
func unsavedSettings(svc Service) []string {
	return svc.BuildAdminSettings().UnsavedSettings
}

// The signer reports a restrictive value whose save failed as unsaved until a
// save of that setting succeeds, whatever else happens to it meanwhile: a
// refused request, a permissive request whose save fails (memory keeps the
// restrictive value), and a retry of the value in effect whose save fails
// again, which tries the save and answers applied_not_saved rather than the
// plain "unchanged" failure. A save that succeeds, or whose file is in place
// with its directory sync failed, clears it, since memory and file then
// agree. The TUI once held this itself, and a retry of the unsaved value was
// classed unchanged.
func TestUnsavedSettingIsReportedUntilASaveSucceeds(t *testing.T) {
	for _, c := range settingChanges() {
		if !c.restrictive {
			continue
		}
		for _, last := range []fsutil.HookOp{"", fsutil.OpDirSync} {
			t.Run(c.name()+"/cleared by "+map[fsutil.HookOp]string{"": "a save", fsutil.OpDirSync: "an unsynced save"}[last], func(t *testing.T) {
				svc, ir, deps := startSettingChange(t, c)
				target := settingTarget(deps.dataDir, c.key)
				update := func(v string) error {
					return svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: v})
				}
				failDurableWriteAt(t, fsutil.OpRename, target)
				if err := update(c.to); protocol.CodeForError(err) != protocol.ResultCodeAppliedNotSaved {
					t.Fatalf("restrictive change: error = %v, want %s", err, protocol.ResultCodeAppliedNotSaved)
				}
				if got := unsavedSettings(svc); !reflect.DeepEqual(got, []string{c.key}) {
					t.Fatalf("unsaved after the failed save = %v, want [%s]", got, c.key)
				}

				if err := update("maybe"); protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
					t.Fatalf("refused value: error = %v", err)
				}
				if err := update(c.from); err == nil || protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved || !strings.Contains(err.Error(), "unchanged") {
					t.Fatalf("permissive change whose save fails: error = %v, want the plain unchanged failure", err)
				}
				requireSetting(t, svc, ir, deps, c.key, c.to, c.from, "after the permissive change's failed save")
				err := update(c.to)
				if protocol.CodeForError(err) != protocol.ResultCodeAppliedNotSaved || !strings.Contains(err.Error(), "not saved") {
					t.Fatalf("retry of the unsaved value: error = %v (code %q), want %s", err, protocol.CodeForError(err), protocol.ResultCodeAppliedNotSaved)
				}
				if got := unsavedSettings(svc); !reflect.DeepEqual(got, []string{c.key}) {
					t.Fatalf("unsaved after the refusal, the failed permissive save and the failed retry = %v, want [%s]", got, c.key)
				}

				fsutil.TestHook = nil
				if last == fsutil.OpDirSync {
					failDurableWriteAt(t, fsutil.OpDirSync, filepath.Dir(target))
					if err := update(c.to); protocol.CodeForError(err) != protocol.ResultCodeAppliedNotDurable {
						t.Fatalf("unsynced retry: error = %v, want %s", err, protocol.ResultCodeAppliedNotDurable)
					}
					fsutil.TestHook = nil
				} else if err := update(c.to); err != nil {
					t.Fatalf("retry that saves: error = %v", err)
				}
				if got := unsavedSettings(svc); len(got) != 0 {
					t.Fatalf("unsaved after the save = %v, want none", got)
				}
				requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the save")
			})
		}
	}
}

// A restrictive value is published before the external-edit check, so it is
// in effect even when the check refuses the update; it is then in effect but
// not saved, answered and reported as for a failed save. A permissive value
// the check refuses is not applied. The check once ran first, so a refused
// restrictive change left the permissive value in effect.
func TestRestrictiveValueIsInEffectWhenTheExternalEditCheckRefuses(t *testing.T) {
	for _, c := range settingChanges() {
		if c.key == adminproto.AdminSettingTheme {
			continue
		}
		t.Run(c.name(), func(t *testing.T) {
			svc, ir, deps := startSettingChange(t, c)
			// Root config.yaml no longer matches the startup config.
			if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\nuser_auto_approve: true\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			err := svc.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			if err == nil || !strings.Contains(err.Error(), "modified externally") {
				t.Fatalf("UpdateAdminSetting error = %v, want the external-edit refusal", err)
			}
			if c.restrictive {
				if protocol.CodeForError(err) != protocol.ResultCodeAppliedNotSaved || !strings.Contains(err.Error(), "in effect now, but it was not saved") {
					t.Fatalf("UpdateAdminSetting error = %v (code %q), want %s", err, protocol.CodeForError(err), protocol.ResultCodeAppliedNotSaved)
				}
				requireSetting(t, svc, ir, deps, c.key, c.to, c.from, "after the refusal")
				if got := unsavedSettings(svc); !reflect.DeepEqual(got, []string{c.key}) {
					t.Fatalf("unsaved after the refusal = %v, want [%s]", got, c.key)
				}
				return
			}
			if protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved {
				t.Fatalf("UpdateAdminSetting error = %v, want a plain refusal", err)
			}
			requireSetting(t, svc, ir, deps, c.key, c.from, c.from, "after the refusal")
			if got := unsavedSettings(svc); len(got) != 0 {
				t.Fatalf("unsaved after a permissive refusal = %v, want none", got)
			}
		})
	}
}
