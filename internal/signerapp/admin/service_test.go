// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

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
	sshInfo  SSHInfo
	mu       sync.Mutex

	identityMutationCalls int
	warningsMu            sync.Mutex
	warnings              []string
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

func (d *fakeDeps) SSHInfo() SSHInfo {
	return d.sshInfo
}

// Warnf records the warning. It runs under the mutation lock d.mu stands
// for, so it takes its own.
func (d *fakeDeps) Warnf(format string, args ...any) {
	d.warningsMu.Lock()
	defer d.warningsMu.Unlock()
	d.warnings = append(d.warnings, fmt.Sprintf(format, args...))
}

func (d *fakeDeps) WithStoreMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.identityMutationCalls++
	return fn()
}

// builtinNetworksChain is a chain view with only the built-in networks and
// no assets.
type builtinNetworksChain struct{}

func (builtinNetworksChain) Networks() apconfig.GenesisHashNetworkResolver {
	return apconfig.DefaultGenesisHashNetworkResolver()
}

func (builtinNetworksChain) ReadAsset(context.Context, []byte, uint64) (models.AssetParams, error) {
	return models.AssetParams{}, errors.New("no assets")
}

type settingAuditRecord struct {
	kind, opID, key, oldValue, newValue string
}

type fakeSettingAudit struct {
	mu        sync.Mutex
	records   []settingAuditRecord
	intentErr error
}

func (a *fakeSettingAudit) LogSettingChangeIntentDurable(_ context.Context, opID, key, oldValue, newValue string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.intentErr != nil {
		return a.intentErr
	}
	a.records = append(a.records, settingAuditRecord{kind: "intent", opID: opID, key: key, oldValue: oldValue, newValue: newValue})
	return nil
}

func (a *fakeSettingAudit) LogSettingChanged(_ context.Context, opID, key, oldValue, newValue string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, settingAuditRecord{kind: "changed", opID: opID, key: key, oldValue: oldValue, newValue: newValue})
}

func (a *fakeSettingAudit) snapshot() []settingAuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]settingAuditRecord(nil), a.records...)
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
	deps := &fakeDeps{
		dataDir:  tmpDir,
		config:   &cfg,
		keyPaths: keyPaths,
	}
	keyStore := keystore.NewFileKeyStore()
	ir := productruntime.New(productruntime.Config{
		KeyStore: keyStore,
		KeyPaths: keyPaths,
		NodeRole: role,
	})
	return Service{Deps: deps, Runtime: ir, ASAChain: builtinNetworksChain{}, Audit: &fakeSettingAudit{}}, ir, deps
}

func TestServiceReportsTheRuntimeUnlockMethod(t *testing.T) {
	svc, _, deps := setupAdminService(t)
	if got := svc.BuildAdminSettings().PassphraseMethod; got != "none" {
		t.Fatalf("prompt runtime: PassphraseMethod = %q, want none", got)
	}

	// A helper written after startup takes effect at the next start, so the
	// running signer still reports prompt mode.
	if err := unlockconfig.SaveUnlockConfig(deps.dataDir, &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", "/tmp/secret"},
	}); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}
	if got := svc.BuildAdminSettings().PassphraseMethod; got != "none" {
		t.Fatalf("after unlock.yaml: PassphraseMethod = %q, want the runtime's none", got)
	}

	headless := Service{Deps: deps, Runtime: productruntime.New(productruntime.Config{UnlockMethod: "passfile"})}
	if got := headless.BuildAdminSettings().PassphraseMethod; got != "passfile" {
		t.Fatalf("headless runtime: PassphraseMethod = %q, want passfile", got)
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
			deps.sshInfo = SSHInfo{Port: 64804}

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

// Every writable setting, theme included, saves the product runtime config
// under the store mutation lock.
func TestUpdateAdminSettingUsesExpectedMutationLock(t *testing.T) {
	for _, req := range []adminproto.UpdateAdminSettingRequest{
		{Key: adminproto.AdminSettingTheme, Value: "dark"},
		{Key: adminproto.AdminSettingUserAutoApprove, Value: "true"},
	} {
		t.Run(req.Key, func(t *testing.T) {
			svc, _, deps := setupAdminService(t)
			if err := svc.UpdateAdminSetting(context.Background(), req); err != nil {
				t.Fatalf("UpdateAdminSetting(%s) error = %v", req.Key, err)
			}
			if deps.identityMutationCalls != 1 {
				t.Fatalf("identityMutationCalls = %d, want 1", deps.identityMutationCalls)
			}
		})
	}
}

// Only the writable settings can be updated. Settings read from config.yaml
// alone, such as the SSH listener address and the advertised endpoint URL, are
// refused like any key the signer does not know, and nothing is saved.
func TestUpdateAdminSettingRefusesKeysThatAreNotWritable(t *testing.T) {
	for _, key := range []string{"ssh.listen_address", "endpoint.advertise_url", "approval_wait", "no_such_setting"} {
		t.Run(key, func(t *testing.T) {
			svc, _, deps := setupAdminService(t)
			before, err := productruntime.LoadStoredConfig(deps.dataDir)
			if err != nil {
				t.Fatal(err)
			}

			err = svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: key, Value: "0.0.0.0"})
			if want := "unknown or read-only setting: " + key; err == nil || err.Error() != want {
				t.Fatalf("UpdateAdminSetting(%s) error = %v, want %q", key, err, want)
			}
			if code := protocol.CodeForError(err); code != protocol.ErrCodeInvalidRequest {
				t.Fatalf("UpdateAdminSetting(%s) code = %q, want %q", key, code, protocol.ErrCodeInvalidRequest)
			}
			if deps.config.Endpoint.SSH.ListenAddress != apconfig.DefaultSSHListenAddress || deps.config.Endpoint.AdvertiseURL != "" {
				t.Fatalf("endpoint config changed: %+v", deps.config.Endpoint)
			}
			after, err := productruntime.LoadStoredConfig(deps.dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("stored config changed: %+v -> %+v", before, after)
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
	effective, err := stored.Apply(productruntime.EffectiveConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !effective.RequireContained || !effective.RequireCosigner {
		t.Fatalf("effective config = %+v", effective)
	}
}

func TestGenerationRequirementSettingsTakeEffectAndPersist(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	for _, test := range []struct {
		key                     string
		wantAdmin, wantCosigner bool
	}{
		{adminproto.AdminSettingRequireContained, true, false},
		{adminproto.AdminSettingRequireCosigner, true, true},
	} {
		if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: test.key, Value: "true"}); err != nil {
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
	effective, err := stored.Apply(productruntime.EffectiveConfig{})
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
	ir.Config().SetGenerationRequirements(false, true)
	// A directory where the runtime config belongs makes the save fail.
	if err := os.MkdirAll(productruntime.ConfigPath(deps.dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingRequireContained, Value: "true"})
	if protocol.CodeForError(err) != protocol.ResultCodeAppliedNotSaved {
		t.Fatalf("turning a requirement on: error = %v, want %s", err, protocol.ResultCodeAppliedNotSaved)
	}
	if contained, _ := ir.Config().GenerationRequirements(); !contained {
		t.Fatal("a requirement turned on is not in effect after its save failed")
	}
	err = svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingRequireCosigner, Value: "false"})
	if err == nil || protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved {
		t.Fatalf("turning a requirement off: error = %v, want a plain save failure", err)
	}
	if _, cosigner := ir.Config().GenerationRequirements(); !cosigner {
		t.Fatal("a requirement turned off was applied after its save failed")
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
				// Every setting on, so a value read as false would show.
				for _, k := range boolSettingKeys {
					if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: k, Value: "true"}); err != nil {
						t.Fatalf("UpdateAdminSetting(%s=true) error = %v", k, err)
					}
				}
				before := svc.BuildAdminSettings()
				diskBefore, err := os.ReadFile(productruntime.ConfigPath(deps.dataDir))
				if err != nil {
					t.Fatal(err)
				}

				err = svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: key, Value: value})
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

// settingChanges is every writable setting in each direction. Only the four
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

// settingTarget is the file key is saved in: the product runtime config,
// for every setting.
func settingTarget(dataDir, _ string) string {
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
		return cfg.Theme()
	}
	t.Fatalf("no live reader for %s", key)
	return ""
}

// storedSetting is the value the next start loads.
func storedSetting(t *testing.T, dataDir, key string) string {
	t.Helper()
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
	case adminproto.AdminSettingTheme:
		return stored.Theme
	}
	t.Fatalf("no stored reader for %s", key)
	return ""
}

// startSettingChange sets c.from, both live and saved.
func startSettingChange(t *testing.T, c settingChange) (Service, *productruntime.Runtime, *fakeDeps) {
	t.Helper()
	svc, ir, deps := setupAdminService(t)
	if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.from}); err != nil {
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
				return svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
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
// that says so; memory never goes back to the permissive value it replaced,
// and the next update is not refused.
func TestUpdateAdminSettingFailureBeforeRename(t *testing.T) {
	for _, c := range settingChanges() {
		for _, op := range []fsutil.HookOp{fsutil.OpFileSync, fsutil.OpRename} {
			t.Run(c.name()+"/"+string(op), func(t *testing.T) {
				svc, ir, deps := startSettingChange(t, c)
				failDurableWriteAt(t, op, settingTarget(deps.dataDir, c.key))

				err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
				fsutil.TestHook = nil
				var saveErr *adminproto.SettingSaveError
				if !errors.As(err, &saveErr) || saveErr.Key != c.key || saveErr.InEffect != c.restrictive {
					t.Fatalf("UpdateAdminSetting error = %v, want a save error for %s, in effect %v", err, c.key, c.restrictive)
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
				if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to}); err != nil {
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
// the old value"), although nothing changed.
func TestUnchangedValueWhoseSaveFailsReportsNothingInEffect(t *testing.T) {
	for _, c := range settingChanges() {
		if !c.restrictive {
			continue
		}
		t.Run(c.key+"="+c.to, func(t *testing.T) {
			same := settingChange{key: c.key, from: c.to, to: c.to}
			svc, ir, deps := startSettingChange(t, same)
			failDurableWriteAt(t, fsutil.OpRename, settingTarget(deps.dataDir, c.key))

			err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			fsutil.TestHook = nil
			if err == nil || protocol.CodeForError(err) == protocol.ResultCodeAppliedNotSaved || !strings.Contains(err.Error(), "unchanged") {
				t.Fatalf("UpdateAdminSetting error = %v (code %q), want the plain unchanged failure", err, protocol.CodeForError(err))
			}
			requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the failed save")
		})
	}
}

// A save whose directory flush fails after its rename has put the new file in
// place, which is what the next start loads. The flush is best effort: a
// failed one does not say the change missed the disk, so the update is a
// success, in either direction, and the signer logs one warning naming the
// setting and the flush error.
func TestUpdateAdminSettingFailureAfterRenameIsASuccessWithAWarning(t *testing.T) {
	for _, c := range settingChanges() {
		t.Run(c.name(), func(t *testing.T) {
			svc, ir, deps := startSettingChange(t, c)
			failDurableWriteAt(t, fsutil.OpDirSync, filepath.Dir(settingTarget(deps.dataDir, c.key)))

			err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			fsutil.TestHook = nil
			if err != nil {
				t.Fatalf("UpdateAdminSetting error = %v, want success", err)
			}
			if len(deps.warnings) != 1 || !strings.Contains(deps.warnings[0], c.key) || !strings.Contains(deps.warnings[0], "injected dir-sync failure") {
				t.Fatalf("warnings = %q, want one naming %s and the flush error", deps.warnings, c.key)
			}
			requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after the unsynced save")
			// The next change goes through as usual.
			if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.from}); err != nil {
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
					return svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: v})
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
					if err := update(c.to); err != nil {
						t.Fatalf("unsynced retry: error = %v, want success", err)
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

// The product runtime config is read when the signer starts: an edit to the
// file while it runs takes effect at the next start, and a setting changed
// through the admin protocol rewrites only its own key. Hand edits to other
// keys therefore stay in the file, do not change what is in effect, and do
// not stop the update. The update was once refused while root config.yaml
// differed from the startup configuration.
func TestSettingSaveKeepsAHandEditToAnotherKey(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingUserAutoApprove, Value: "false"}); err != nil {
		t.Fatal(err)
	}
	identityPath := productruntime.ConfigPath(deps.dataDir)
	// A hand edit while the signer runs, to a key the updates below leave
	// alone.
	if err := os.WriteFile(identityPath, []byte("user_auto_approve: false\nlock_on_disconnect: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, req := range []adminproto.UpdateAdminSettingRequest{
		{Key: adminproto.AdminSettingUserAutoApprove, Value: "true"},
		{Key: adminproto.AdminSettingTheme, Value: "dark"},
	} {
		if err := svc.UpdateAdminSetting(context.Background(), req); err != nil {
			t.Fatalf("UpdateAdminSetting(%s=%s) after a hand edit: %v", req.Key, req.Value, err)
		}
	}
	stored, err := productruntime.LoadStoredConfig(deps.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UserAutoApprove == nil || !*stored.UserAutoApprove || stored.LockOnDisconnect == nil || !*stored.LockOnDisconnect || stored.Theme != "dark" {
		t.Fatalf("identity config = %+v, want user_auto_approve and theme replaced and the hand-edited lock_on_disconnect kept", stored)
	}
	if ir.Config().LockOnDisconnect() {
		t.Fatal("a hand edit took effect while the signer runs")
	}
}

// No setting change writes the process-global config.yaml, whose comments
// and key order are the operator's: every one, theme included, is saved to
// the product runtime config. A theme change once rewrote config.yaml through
// a map, which dropped every comment and sorted the keys.
func TestSettingChangesLeaveRootConfigUntouched(t *testing.T) {
	svc, _, deps := setupAdminService(t)
	rootPath := filepath.Join(deps.dataDir, "config.yaml")
	root := []byte("# Operator notes.\npassphrase_timeout: \"15m\"\napproval_wait: 7m # long reviews\n")
	if err := os.WriteFile(rootPath, root, 0o640); err != nil {
		t.Fatal(err)
	}

	for _, c := range settingChanges() {
		if err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to}); err != nil {
			t.Fatalf("UpdateAdminSetting(%s=%s) error = %v", c.key, c.to, err)
		}
	}
	if got, err := os.ReadFile(rootPath); err != nil || !bytes.Equal(got, root) {
		t.Fatalf("root config.yaml after the setting changes = %q, %v; want it unchanged:\n%s", got, err, root)
	}
	if got := svc.BuildAdminSettings().Theme; got != "dark" {
		t.Fatalf("admin settings theme = %q, want dark", got)
	}
	if saved, err := os.ReadFile(productruntime.ConfigPath(deps.dataDir)); err != nil || !bytes.Contains(saved, []byte("theme: dark")) {
		t.Fatalf("product runtime config = %q, %v; want the theme saved there", saved, err)
	}
}

// A restrictive value is reported unsaved from the moment it is published,
// before its save, so a save that hangs leaves it listed; the save that puts
// the new file in place clears it. A permissive value is never listed. The
// setting was once marked unsaved only when the save returned an error, so a
// hung save showed nothing. admin_settings takes no lock the update holds.
func TestRestrictiveValueIsReportedUnsavedWhileItsSaveIsHeld(t *testing.T) {
	for _, c := range settingChanges() {
		t.Run(c.name(), func(t *testing.T) {
			svc, _, deps := startSettingChange(t, c)
			held := fsutiltest.Hold(t, fsutil.OpRename, settingTarget(deps.dataDir, c.key), func() error {
				return svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{Key: c.key, Value: c.to})
			})
			if got := unsavedSettings(svc); slices.Contains(got, c.key) != c.restrictive {
				t.Fatalf("unsaved during the held save = %v, want %s listed only for a restrictive change (%v)", got, c.key, c.restrictive)
			}
			if err := held.Finish(nil); err != nil {
				t.Fatalf("UpdateAdminSetting error = %v", err)
			}
			if got := unsavedSettings(svc); len(got) != 0 {
				t.Fatalf("unsaved after the save = %v, want none", got)
			}
		})
	}
}

// Non-restrictive setting updates (loosening a boolean setting, changing
// passphrase_timeout or theme, or re-saving an already-saved value) wait for
// a durable SETTING_CHANGE_INTENT before saving or publishing. Missing audit
// refuses with audit_unavailable, and a write failure refuses with
// audit_write_failed, leaving both memory and disk untouched.
func TestNonRestrictiveSettingRequiresDurableAuditBeforeSave(t *testing.T) {
	for _, c := range settingChanges() {
		if c.restrictive {
			continue
		}
		for _, mode := range []string{"unavailable", "write_failed", "durable"} {
			t.Run(c.name()+"/"+mode, func(t *testing.T) {
				svc, ir, deps := startSettingChange(t, c)
				switch mode {
				case "unavailable":
					svc.Audit = nil
				case "write_failed":
					svc.Audit = &fakeSettingAudit{intentErr: errors.New("audit disk full")}
				case "durable":
					svc.Audit = &fakeSettingAudit{}
				}
				err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{
					OperationID: "op-1", Key: c.key, Value: c.to,
				})
				switch mode {
				case "unavailable":
					if code := protocol.CodeForError(err); code != protocol.ResultCodeAuditUnavailable {
						t.Fatalf("error = %v (code %q), want %s", err, code, protocol.ResultCodeAuditUnavailable)
					}
					requireSetting(t, svc, ir, deps, c.key, c.from, c.from, "after audit unavailable refusal")
				case "write_failed":
					if code := protocol.CodeForError(err); code != protocol.ResultCodeAuditWriteFailed {
						t.Fatalf("error = %v (code %q), want %s", err, code, protocol.ResultCodeAuditWriteFailed)
					}
					requireSetting(t, svc, ir, deps, c.key, c.from, c.from, "after audit write failure")
				case "durable":
					if err != nil {
						t.Fatalf("UpdateAdminSetting error = %v", err)
					}
					requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after durable audit and save")
					records := svc.Audit.(*fakeSettingAudit).snapshot()
					if len(records) != 2 || records[0].kind != "intent" || records[1].kind != "changed" {
						t.Fatalf("audit records = %+v, want [intent, changed]", records)
					}
					for _, rec := range records {
						if rec.opID != "op-1" || rec.key != c.key {
							t.Fatalf("audit record = %+v, want op-1 and key %s", rec, c.key)
						}
					}
				}
			})
		}
	}
}

// Restrictive setting updates (turning user_auto_approve off, or enabling
// require_contained, require_cosigner or lock_on_disconnect) apply and save
// even when the audit log is unavailable or failing, so an audit failure
// never blocks locking down. When the audit log is present, the saved change
// emits SETTING_CHANGED without blocking on SETTING_CHANGE_INTENT.
func TestRestrictiveSettingAppliesEvenWhenAuditUnavailableOrFailing(t *testing.T) {
	for _, c := range settingChanges() {
		if !c.restrictive {
			continue
		}
		for _, mode := range []string{"unavailable", "write_failed", "healthy"} {
			t.Run(c.name()+"/"+mode, func(t *testing.T) {
				svc, ir, deps := startSettingChange(t, c)
				switch mode {
				case "unavailable":
					svc.Audit = nil
				case "write_failed":
					svc.Audit = &fakeSettingAudit{intentErr: errors.New("audit disk full")}
				case "healthy":
					svc.Audit = &fakeSettingAudit{}
				}
				err := svc.UpdateAdminSetting(context.Background(), adminproto.UpdateAdminSettingRequest{
					OperationID: "op-lockdown", Key: c.key, Value: c.to,
				})
				if err != nil {
					t.Fatalf("restrictive change under audit %s failed: %v", mode, err)
				}
				requireSetting(t, svc, ir, deps, c.key, c.to, c.to, "after restrictive change")
				if mode == "healthy" {
					records := svc.Audit.(*fakeSettingAudit).snapshot()
					if len(records) != 1 || records[0].kind != "changed" ||
						records[0].opID != "op-lockdown" || records[0].key != c.key ||
						records[0].oldValue != c.from || records[0].newValue != c.to {
						t.Fatalf("audit records = %+v, want one changed record %s %s->%s", records, c.key, c.from, c.to)
					}
				}
			})
		}
	}
}
