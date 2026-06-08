// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type fakeDeps struct {
	dataDir  string
	config   *apconfig.ServerConfig
	keyPaths storepaths.Paths
	theme    string
	sshInfo  SSHInfo
	mu       sync.Mutex

	processMutationCalls  int
	identityMutationCalls int
	restartSSHCalls       []string
	restartSSHErr         error
}

func (d *fakeDeps) DataDir() string {
	return d.dataDir
}

func (d *fakeDeps) Config() *apconfig.ServerConfig {
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

func (d *fakeDeps) SetSSHListenAddress(v string) {
	d.config.SSH.ListenAddress = v
}

func (d *fakeDeps) SetEndpointAdvertiseURL(v string) {
	d.config.Endpoint.AdvertiseURL = v
}

func (d *fakeDeps) RestartSSHListener(listenAddress string) error {
	d.restartSSHCalls = append(d.restartSSHCalls, listenAddress)
	return d.restartSSHErr
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

func (d *fakeDeps) WithIdentityMutation(identityID string, fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.identityMutationCalls++
	return fn()
}

func setupAdminService(t *testing.T) (Service, *identity.Runtime, *fakeDeps) {
	return setupAdminServiceWithRole(t, noderole.RoleSigner)
}

func setupAdminServiceWithRole(t *testing.T, role noderole.Role) (Service, *identity.Runtime, *fakeDeps) {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	if err := os.MkdirAll(keyPaths.KeysDir(auth.DefaultIdentityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keysDir): %v", err)
	}

	cfg := apconfig.DefaultServerConfig()
	cfg.Theme = "auto"
	deps := &fakeDeps{
		dataDir:  tmpDir,
		config:   &cfg,
		keyPaths: keyPaths,
		theme:    cfg.Theme,
	}
	keyStore := keystore.NewFileKeyStoreForPaths(keyPaths, auth.DefaultIdentityID)
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      keyStore,
		KeyPaths:      keyPaths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		NodeRole:      role,
	})
	return Service{Deps: deps}, ir, deps
}

func unlockAdminServicePolicyTest(t *testing.T, svc Service, ir *identity.Runtime, target adminproto.PolicyTarget, stored *policy.StoredConfig) {
	t.Helper()

	passphrase := []byte("admin-policy-test-passphrase")
	_, masterKey, err := securecrypto.CreateKeystoreMetadata(ir.KeyPaths().KeystoreMetadataDir(ir.ID()), passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata(): %v", err)
	}
	securecrypto.ZeroBytes(masterKey)
	if _, err := ir.KeyStore().InitializeMasterKey(passphrase); err != nil {
		t.Fatalf("InitializeMasterKey(): %v", err)
	}
	ir.SetUnlocked()

	err = ir.WithMasterKey(func(masterKey []byte) error {
		switch target {
		case adminproto.PolicyTargetSentry:
			if err := policy.SaveStoredSentryConfigWithMasterKey(svc.Deps.DataDir(), ir.ID(), stored, masterKey, testPolicyTime()); err != nil {
				return err
			}
			verified, effective, err := policyruntime.LoadVerifiedSentryWithStored(svc.Deps.DataDir(), ir.ID(), svc.Deps.Config(), masterKey)
			if err != nil {
				return err
			}
			ir.SetSentryPolicyState(verified, effective)
		default:
			if err := policy.SaveStoredConfigWithMasterKey(svc.Deps.DataDir(), ir.ID(), stored, masterKey, testPolicyTime()); err != nil {
				return err
			}
			verified, effective, err := policyruntime.LoadVerifiedWithStored(svc.Deps.DataDir(), ir.ID(), svc.Deps.Config(), masterKey)
			if err != nil {
				return err
			}
			ir.SetPolicyState(verified, effective)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("install initial %s policy: %v", target, err)
	}
}

func testPolicyTime() time.Time {
	return time.Unix(1700000000, 0)
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

func TestServiceDetectPassphraseMethodForIdentityReadsUnlockYAML(t *testing.T) {
	svc, ir, deps := setupAdminService(t)

	got := svc.detectPassphraseMethodForIdentity(ir, deps.config)
	if got != "none" {
		t.Fatalf("before unlock.yaml: got %q, want %q", got, "none")
	}

	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(deps.dataDir, auth.DefaultIdentityID, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	got = svc.detectPassphraseMethodForIdentity(ir, deps.config)
	if got != "passfile" {
		t.Fatalf("after unlock.yaml with appass-file: got %q, want %q", got, "passfile")
	}
}

func TestServiceDetectPassphraseMethodForIdentityFallsBackToGlobalConfig(t *testing.T) {
	svc, ir, deps := setupAdminService(t)

	deps.config.PassphraseCommandArgv = []string{"/usr/bin/appass-systemd-creds"}

	got := svc.detectPassphraseMethodForIdentity(ir, deps.config)
	if got != "systemd-creds" {
		t.Fatalf("global fallback: got %q, want %q", got, "systemd-creds")
	}
}

func TestServiceDetectPassphraseMethodForIdentityIdentityScopedOverridesGlobal(t *testing.T) {
	svc, ir, deps := setupAdminService(t)

	deps.config.PassphraseCommandArgv = []string{"/usr/bin/appass-systemd-creds"}
	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(deps.dataDir, auth.DefaultIdentityID, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	got := svc.detectPassphraseMethodForIdentity(ir, deps.config)
	if got != "passfile" {
		t.Fatalf("identity-scoped should override global: got %q, want %q", got, "passfile")
	}
}

func TestUpdateAdminSettingUsesExpectedMutationLock(t *testing.T) {
	t.Run("theme uses process config mutation lock", func(t *testing.T) {
		svc, ir, deps := setupAdminService(t)
		if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
			t.Fatal(err)
		}

		if err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingTheme, Value: "dark"}); err != nil {
			t.Fatalf("UpdateAdminSetting(theme) error = %v", err)
		}
		if deps.processMutationCalls != 1 {
			t.Fatalf("processMutationCalls = %d, want 1", deps.processMutationCalls)
		}
		if deps.identityMutationCalls != 0 {
			t.Fatalf("identityMutationCalls = %d, want 0", deps.identityMutationCalls)
		}
	})

	t.Run("identity setting uses identity mutation lock", func(t *testing.T) {
		svc, ir, deps := setupAdminService(t)
		if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
			t.Fatal(err)
		}

		if err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{Key: adminproto.AdminSettingUserAutoApprove, Value: "true"}); err != nil {
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

func TestUpdateAdminSettingEndpointAdvertiseURLPersistsServerConfig(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingEndpointAdvertiseURL,
		Value: "ssh://signer.example:1127/",
	}); err != nil {
		t.Fatalf("UpdateAdminSetting(endpoint.advertise_url) error = %v", err)
	}
	if deps.processMutationCalls != 1 {
		t.Fatalf("processMutationCalls = %d, want 1", deps.processMutationCalls)
	}
	if deps.identityMutationCalls != 0 {
		t.Fatalf("identityMutationCalls = %d, want 0", deps.identityMutationCalls)
	}

	disk, err := apconfig.LoadServerConfig(deps.dataDir)
	if err != nil {
		t.Fatalf("LoadServerConfig error = %v", err)
	}
	if disk.Endpoint.AdvertiseURL != "ssh://signer.example:1127" {
		t.Fatalf("disk Endpoint.AdvertiseURL = %q", disk.Endpoint.AdvertiseURL)
	}

	settings := svc.BuildAdminSettings(ir)
	if settings.EndpointAdvertiseURL != "ssh://signer.example:1127" {
		t.Fatalf("settings EndpointAdvertiseURL = %q", settings.EndpointAdvertiseURL)
	}
}

func TestUpdateAdminSettingEndpointAdvertiseURLRejectsInvalidValue(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingEndpointAdvertiseURL,
		Value: "self",
	})
	if err == nil {
		t.Fatal("UpdateAdminSetting(endpoint.advertise_url self) error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), "invalid endpoint.advertise_url") {
		t.Fatalf("UpdateAdminSetting error = %v, want endpoint.advertise_url", err)
	}
	if deps.config.Endpoint.AdvertiseURL != "" {
		t.Fatalf("Endpoint.AdvertiseURL = %q, want unchanged empty", deps.config.Endpoint.AdvertiseURL)
	}
}

func TestUpdateAdminSettingSSHListenAddressPersistsServerConfigAndRestarts(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	initial := `theme: auto
ssh:
  listen_address: 127.0.0.1
  port: 2222
  host_key_path: .ssh/custom_host_key
  authorized_keys_path: .ssh/custom_authorized_keys
`
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte(initial), 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, err := apconfig.LoadServerConfig(deps.dataDir)
	if err != nil {
		t.Fatalf("LoadServerConfig initial error = %v", err)
	}
	deps.config = &loaded

	if err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingSSHListenAddress,
		Value: "0.0.0.0",
	}); err != nil {
		t.Fatalf("UpdateAdminSetting(ssh.listen_address) error = %v", err)
	}
	if deps.processMutationCalls != 1 {
		t.Fatalf("processMutationCalls = %d, want 1", deps.processMutationCalls)
	}
	if deps.identityMutationCalls != 0 {
		t.Fatalf("identityMutationCalls = %d, want 0", deps.identityMutationCalls)
	}
	if got := strings.Join(deps.restartSSHCalls, ","); got != "0.0.0.0" {
		t.Fatalf("restartSSHCalls = %q, want 0.0.0.0", got)
	}

	disk, err := apconfig.LoadServerConfig(deps.dataDir)
	if err != nil {
		t.Fatalf("LoadServerConfig error = %v", err)
	}
	if disk.SSH.ListenAddress != "0.0.0.0" {
		t.Fatalf("disk SSH.ListenAddress = %q, want 0.0.0.0", disk.SSH.ListenAddress)
	}
	if disk.SSH.Port != 2222 {
		t.Fatalf("disk SSH.Port = %d, want 2222", disk.SSH.Port)
	}
	if !strings.HasSuffix(disk.SSH.HostKeyPath, ".ssh/custom_host_key") {
		t.Fatalf("disk SSH.HostKeyPath = %q, want preserved custom path", disk.SSH.HostKeyPath)
	}
	if !strings.HasSuffix(disk.SSH.AuthorizedKeysPath, ".ssh/custom_authorized_keys") {
		t.Fatalf("disk SSH.AuthorizedKeysPath = %q, want preserved custom path", disk.SSH.AuthorizedKeysPath)
	}

	settings := svc.BuildAdminSettings(ir)
	if settings.SSHListenAddress != "0.0.0.0" {
		t.Fatalf("settings SSHListenAddress = %q, want 0.0.0.0", settings.SSHListenAddress)
	}
}

func TestUpdateAdminSettingSSHListenAddressRejectsInvalidValue(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingSSHListenAddress,
		Value: "127.0.0.1:1127",
	})
	if err == nil {
		t.Fatal("UpdateAdminSetting(ssh.listen_address with port) error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), "invalid ssh.listen_address") {
		t.Fatalf("UpdateAdminSetting error = %v, want ssh.listen_address", err)
	}
	if deps.config.SSH.ListenAddress != apconfig.DefaultSSHListenAddress {
		t.Fatalf("SSH.ListenAddress = %q, want unchanged default", deps.config.SSH.ListenAddress)
	}
	if len(deps.restartSSHCalls) != 0 {
		t.Fatalf("restartSSHCalls = %v, want none", deps.restartSSHCalls)
	}
}

func TestUpdateAdminSettingSSHListenAddressDoesNotPersistWhenRestartFails(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	if err := os.WriteFile(filepath.Join(deps.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	deps.restartSSHErr = fmt.Errorf("bind failed")

	err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingSSHListenAddress,
		Value: "0.0.0.0",
	})
	if err == nil {
		t.Fatal("UpdateAdminSetting(ssh.listen_address) error = nil, want restart failure")
	}
	if !strings.Contains(err.Error(), "failed to update SSH listener") {
		t.Fatalf("UpdateAdminSetting error = %v, want listener failure", err)
	}
	if got := strings.Join(deps.restartSSHCalls, ","); got != "0.0.0.0" {
		t.Fatalf("restartSSHCalls = %q, want 0.0.0.0", got)
	}
	if deps.config.SSH.ListenAddress != apconfig.DefaultSSHListenAddress {
		t.Fatalf("SSH.ListenAddress = %q, want unchanged default", deps.config.SSH.ListenAddress)
	}

	disk, loadErr := apconfig.LoadServerConfig(deps.dataDir)
	if loadErr != nil {
		t.Fatalf("LoadServerConfig error = %v", loadErr)
	}
	if disk.SSH.ListenAddress != apconfig.DefaultSSHListenAddress {
		t.Fatalf("disk SSH.ListenAddress = %q, want unchanged default", disk.SSH.ListenAddress)
	}
}

func TestSearchASAMetadataUsesSignerCacheOnly(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	deps.config.Algod = apconfig.AlgodConfig{
		"customnet": {Server: "http://127.0.0.1:1", Token: ""},
	}

	metadataStore := asametadata.NewStore(deps.dataDir)
	for _, meta := range []asa.Metadata{
		{AssetID: 44, Name: "Second Duplicate", UnitName: "DUP", Decimals: 6},
		{AssetID: 11, Name: "First Duplicate", UnitName: "dup", Decimals: 2},
		{AssetID: 99, Name: "Different", UnitName: "OTHER", Decimals: 0},
	} {
		if err := metadataStore.SaveLocalMetadata("customnet", meta); err != nil {
			t.Fatalf("SaveLocalMetadata() error = %v", err)
		}
	}

	result := svc.SearchASAMetadata(ir, adminproto.SearchASAMetadataRequest{
		Network: "customnet",
		Query:   "DuP",
	})
	if result.Error != "" || result.Code != "" {
		t.Fatalf("SearchASAMetadata() error = code %q error %q", result.Code, result.Error)
	}
	if len(result.Results) != 2 {
		t.Fatalf("SearchASAMetadata() returned %d results, want 2: %+v", len(result.Results), result.Results)
	}
	if result.Results[0].AssetID != 11 || result.Results[1].AssetID != 44 {
		t.Fatalf("SearchASAMetadata() asset order = [%d %d], want [11 44]", result.Results[0].AssetID, result.Results[1].AssetID)
	}
	if result.Network != "customnet" || result.Results[0].Source != "cache" {
		t.Fatalf("SearchASAMetadata() result = network %q first %+v, want cache-sourced customnet metadata", result.Network, result.Results[0])
	}
}

func TestSearchASAMetadataRejectsUnconfiguredNetwork(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	deps.config.Algod = apconfig.AlgodConfig{
		"customnet": {Server: "http://127.0.0.1:1", Token: ""},
	}

	result := svc.SearchASAMetadata(ir, adminproto.SearchASAMetadataRequest{
		Network: "othernet",
		Query:   "USDC",
	})
	if result.Code != "network_not_configured" {
		t.Fatalf("SearchASAMetadata() code = %q, want network_not_configured", result.Code)
	}
	if result.Error == "" {
		t.Fatal("SearchASAMetadata() error is empty, want explanatory error")
	}
}

func TestResolveASAMetadataResolvesBuiltinNumericID(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	deps.config.Algod = apconfig.AlgodConfig{
		"testnet": {Server: "http://127.0.0.1:1", Token: ""},
	}

	result := svc.ResolveASAMetadata(ir, adminproto.ResolveASAMetadataRequest{
		Network: "testnet",
		AssetID: 10458941,
	})
	if result.Error != "" || result.Code != "" {
		t.Fatalf("ResolveASAMetadata() error = code %q error %q", result.Code, result.Error)
	}
	if result.Asset.AssetID != 10458941 || result.Asset.UnitName != "USDC" || result.Asset.Decimals != 6 {
		t.Fatalf("ResolveASAMetadata() asset = %+v, want testnet USDC", result.Asset)
	}
}

func TestBuildPolicySettingsIncludesASAMetadataForConfiguredLimits(t *testing.T) {
	svc, ir, deps := setupAdminService(t)
	deps.config.Algod = apconfig.AlgodConfig{
		"testnet": {Server: "http://127.0.0.1:1", Token: ""},
	}
	ir.SetPolicy(&policy.Config{
		ReviewAlgoPayments: map[string]uint64{
			"testnet": 5_250_000,
		},
		MaxAlgoPayments: map[string]uint64{
			"testnet": 10_500_000,
		},
		ReviewASAAmounts: map[string]map[uint64]uint64{
			"testnet": {10458941: 500_000},
		},
		MaxASAAmounts: map[string]map[uint64]uint64{
			"testnet": {10458941: 1_000_000},
		},
	})

	settings := svc.BuildPolicySettings(ir)
	items := settings.PolicyASAMetadata["testnet"]
	if len(items) != 1 {
		t.Fatalf("PolicyASAMetadata[testnet] length = %d, want 1: %+v", len(items), items)
	}
	if items[0].AssetID != 10458941 || items[0].UnitName != "USDC" || items[0].Decimals != 6 {
		t.Fatalf("PolicyASAMetadata[testnet][0] = %+v, want testnet USDC metadata", items[0])
	}
	if settings.MaxAlgoPayments["testnet"] != "10.5" {
		t.Fatalf("MaxAlgoPayments[testnet] = %q, want 10.5", settings.MaxAlgoPayments["testnet"])
	}
	if settings.ReviewAlgoPayments["testnet"] != "5.25" {
		t.Fatalf("ReviewAlgoPayments[testnet] = %q, want 5.25", settings.ReviewAlgoPayments["testnet"])
	}
	if settings.ReviewASAAmounts["testnet"] != "10458941:0.5" {
		t.Fatalf("ReviewASAAmounts[testnet] = %q, want 10458941:0.5", settings.ReviewASAAmounts["testnet"])
	}
}

func TestBuildPolicySnapshotReturnsCanonicalActivePolicy(t *testing.T) {
	svc, ir, _ := setupAdminService(t)
	rejectForeignRekey := false
	maxFee := uint64(7000)
	stored := &policy.StoredConfig{
		RejectForeignRekey: &rejectForeignRekey,
		MaxFeeMicroAlgos:   &maxFee,
	}
	effective := policy.DefaultConfig()
	effective.RejectForeignRekey = false
	effective.MaxFeeMicroAlgos = maxFee
	ir.SetPolicyState(stored, effective)

	snapshot := svc.BuildPolicySnapshot(ir, adminproto.PolicyTargetSigner)
	if !snapshot.Success {
		t.Fatalf("BuildPolicySnapshot() success = false, code %q error %q", snapshot.Code, snapshot.Error)
	}
	if snapshot.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("IdentityID = %q, want %q", snapshot.IdentityID, auth.DefaultIdentityID)
	}
	if !snapshot.Canonical {
		t.Fatal("Canonical = false, want true")
	}
	if !strings.Contains(snapshot.PolicyYAML, "reject_foreign_rekey: false") ||
		!strings.Contains(snapshot.PolicyYAML, "max_fee_microalgos: 7000") {
		t.Fatalf("PolicyYAML missing expected fields:\n%s", snapshot.PolicyYAML)
	}
	sum := sha256.Sum256([]byte(snapshot.PolicyYAML))
	if want := fmt.Sprintf("%x", sum); snapshot.PolicySHA256 != want {
		t.Fatalf("PolicySHA256 = %q, want %q", snapshot.PolicySHA256, want)
	}
}

func TestBuildPolicySnapshotReportsUnavailableSnapshot(t *testing.T) {
	svc, ir, _ := setupAdminService(t)
	ir.SetPolicy(policy.DefaultConfig())

	snapshot := svc.BuildPolicySnapshot(ir, adminproto.PolicyTargetSigner)
	if snapshot.Success {
		t.Fatal("BuildPolicySnapshot() success = true, want false without stored snapshot")
	}
	if snapshot.Code != "policy_snapshot_unavailable" {
		t.Fatalf("Code = %q, want policy_snapshot_unavailable", snapshot.Code)
	}
	if snapshot.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("IdentityID = %q, want %q", snapshot.IdentityID, auth.DefaultIdentityID)
	}
}

func TestBuildSentryPolicySnapshotReturnsCanonicalActivePolicy(t *testing.T) {
	svc, ir, _ := setupAdminServiceWithRole(t, noderole.RoleSentry)
	stored := storedSentryPolicyForAdminTest(t, "allow_initial")
	effective, err := policyruntime.ApplySentryStoredConfig(svc.Deps.DataDir(), svc.Deps.Config(), stored)
	if err != nil {
		t.Fatalf("ApplySentryStoredConfig(): %v", err)
	}
	ir.SetSentryPolicyState(stored, effective)

	snapshot := svc.BuildPolicySnapshot(ir, adminproto.PolicyTargetSentry)
	if !snapshot.Success {
		t.Fatalf("BuildPolicySnapshot(sentry) success = false, code %q error %q", snapshot.Code, snapshot.Error)
	}
	if snapshot.Target != adminproto.PolicyTargetSentry {
		t.Fatalf("Target = %q, want sentry", snapshot.Target)
	}
	if !snapshot.Canonical {
		t.Fatal("Canonical = false, want true")
	}
	if strings.Contains(snapshot.PolicyYAML, "sentry:") {
		t.Fatalf("sentry snapshot contains wrapper:\n%s", snapshot.PolicyYAML)
	}
	if !strings.Contains(snapshot.PolicyYAML, "allow_initial") ||
		!strings.Contains(snapshot.PolicyYAML, "transfer_policy:") {
		t.Fatalf("PolicyYAML missing expected sentry policy fields:\n%s", snapshot.PolicyYAML)
	}
}

func TestValidatePolicyUsesTargetParserAndRoleGate(t *testing.T) {
	svc, signerIR, _ := setupAdminServiceWithRole(t, noderole.RoleSigner)
	sentryYAML := sentryPolicyYAMLForAdminTest("allow_validate")
	result := svc.ValidatePolicy(signerIR, adminproto.ValidatePolicyRequest{
		Target:     adminproto.PolicyTargetSentry,
		PolicyYAML: sentryYAML,
	})
	if result.Success {
		t.Fatalf("ValidatePolicy(sentry on signer) success = true, want false")
	}
	if result.Code != "policy_target_not_allowed_for_node_role" {
		t.Fatalf("Code = %q, want policy_target_not_allowed_for_node_role", result.Code)
	}

	sentrySvc, sentryIR, _ := setupAdminServiceWithRole(t, noderole.RoleSentry)
	result = sentrySvc.ValidatePolicy(sentryIR, adminproto.ValidatePolicyRequest{
		Target:     adminproto.PolicyTargetSentry,
		PolicyYAML: sentryYAML,
	})
	if !result.Success {
		t.Fatalf("ValidatePolicy(sentry) success = false, code %q error %q", result.Code, result.Error)
	}
	if result.Target != adminproto.PolicyTargetSentry {
		t.Fatalf("Target = %q, want sentry", result.Target)
	}
}

func TestReplaceSentryPolicyUpdatesRuntimeAndSidecar(t *testing.T) {
	svc, ir, _ := setupAdminServiceWithRole(t, noderole.RoleSentry)
	initial := storedSentryPolicyForAdminTest(t, "allow_initial")
	unlockAdminServicePolicyTest(t, svc, ir, adminproto.PolicyTargetSentry, initial)
	initialSnapshot := svc.BuildPolicySnapshot(ir, adminproto.PolicyTargetSentry)
	if !initialSnapshot.Success {
		t.Fatalf("initial snapshot success = false, code %q error %q", initialSnapshot.Code, initialSnapshot.Error)
	}

	updatedYAML := sentryPolicyYAMLForAdminTest("allow_updated")
	result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{
		Target:                adminproto.PolicyTargetSentry,
		PolicyYAML:            updatedYAML,
		ExpectedCurrentSHA256: initialSnapshot.PolicySHA256,
	})
	if !result.Success {
		t.Fatalf("ReplacePolicy(sentry) success = false, code %q error %q", result.Code, result.Error)
	}
	if result.Target != adminproto.PolicyTargetSentry {
		t.Fatalf("Target = %q, want sentry", result.Target)
	}
	if !strings.Contains(result.PolicyYAML, "allow_updated") {
		t.Fatalf("result PolicyYAML missing updated route:\n%s", result.PolicyYAML)
	}

	var verified *policy.StoredConfig
	err := ir.WithMasterKey(func(masterKey []byte) error {
		var err error
		verified, err = policy.LoadVerifiedSentryConfigWithMasterKey(svc.Deps.DataDir(), ir.ID(), masterKey)
		return err
	})
	if err != nil {
		t.Fatalf("LoadVerifiedSentryConfigWithMasterKey(): %v", err)
	}
	verifiedData, err := policy.MarshalStoredSentryConfig(verified)
	if err != nil {
		t.Fatalf("MarshalStoredSentryConfig(): %v", err)
	}
	if !strings.Contains(string(verifiedData), "allow_updated") {
		t.Fatalf("verified sentry policy missing updated route:\n%s", verifiedData)
	}
	stored, _ := ir.SentryPolicySnapshot()
	if stored == nil || stored.TransferPolicy == nil || len(stored.TransferPolicy.Routes) != 1 ||
		stored.TransferPolicy.Routes[0].ID != "allow_updated" {
		t.Fatalf("runtime stored sentry policy = %+v, want allow_updated route", stored)
	}
}

func TestReplacePolicyRejectsOppositeNodeRoleTarget(t *testing.T) {
	svc, ir, _ := setupAdminServiceWithRole(t, noderole.RoleSentry)
	result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{
		Target:     adminproto.PolicyTargetSigner,
		PolicyYAML: "reject_foreign_rekey: true\n",
	})
	if result.Success {
		t.Fatal("ReplacePolicy(signer target on sentry) success = true, want false")
	}
	if result.Code != "policy_target_not_allowed_for_node_role" {
		t.Fatalf("Code = %q, want policy_target_not_allowed_for_node_role", result.Code)
	}
}

func storedSentryPolicyForAdminTest(t *testing.T, routeID string) *policy.StoredConfig {
	t.Helper()
	stored, err := policy.ParseStoredSentryConfig([]byte(sentryPolicyYAMLForAdminTest(routeID)))
	if err != nil {
		t.Fatalf("ParseStoredSentryConfig(): %v", err)
	}
	return stored
}

func sentryPolicyYAMLForAdminTest(routeID string) string {
	return fmt.Sprintf(`transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: %s
      networks:
        - '*'
      sources:
        - '*'
      assets:
        - algo
      destinations:
        - '*'
`, routeID)
}
