// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"crypto/sha256"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
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
	if err := os.MkdirAll(keyPaths.LegacyKeysDir(), 0o750); err != nil {
		t.Fatalf("MkdirAll(keysDir): %v", err)
	}

	cfg := serverconfig.DefaultServerConfig()
	cfg.Theme = "auto"
	deps := &fakeDeps{
		dataDir:  tmpDir,
		config:   &cfg,
		keyPaths: keyPaths,
		theme:    cfg.Theme,
	}
	keyStore := keystore.NewFileKeyStoreForPaths(keyPaths)
	ir := productruntime.New(productruntime.Config{

		KeyStore:      keyStore,
		KeyPaths:      keyPaths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		NodeRole:      role,
	})
	return Service{Deps: deps, Runtime: ir}, ir, deps
}

func unlockAdminServicePolicyTest(t *testing.T, svc Service, ir *productruntime.Runtime, target adminproto.PolicyTarget, stored *policy.StoredConfig) {
	t.Helper()

	passphrase := []byte("admin-policy-test-passphrase")
	if _, err := securecrypto.CreateKeyringStore(ir.KeyPaths().KeystoreMetadataDir(), passphrase); err != nil {
		t.Fatalf("CreateKeyringStore(): %v", err)
	}
	if err := ir.KeyStore().Unlock(passphrase); err != nil {
		t.Fatalf("Unlock(): %v", err)
	}
	ir.SetUnlocked()

	err := ir.WithKeyring(func(masterKey *securecrypto.Keyring) error {
		switch target {
		case adminproto.PolicyTargetSentry:
			if err := policy.SaveStoredSentryConfigWithKeyring(svc.Deps.DataDir(), stored, masterKey, testPolicyTime()); err != nil {
				return err
			}
			verified, effective, err := policyruntime.LoadVerifiedSentryWithStored(svc.Deps.DataDir(), svc.Deps.Config(), masterKey)
			if err != nil {
				return err
			}
			ir.SetSentryPolicyState(verified, effective)
		default:
			if err := policy.SaveStoredConfigWithKeyring(svc.Deps.DataDir(), stored, masterKey, testPolicyTime()); err != nil {
				return err
			}
			verified, effective, err := policyruntime.LoadVerifiedWithStored(svc.Deps.DataDir(), svc.Deps.Config(), masterKey)
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

func TestBuildPolicySnapshotReturnsCanonicalActivePolicy(t *testing.T) {
	svc, ir, _ := setupAdminService(t)
	rejectForeignRekey := false
	maxFee := uint64(7000)
	stored := &policy.StoredConfig{StoredPolicyCore: policy.StoredPolicyCore{RejectForeignRekey: &rejectForeignRekey, MaxFeeMicroAlgos: &maxFee}}
	effective := policy.DefaultConfig()
	effective.RejectForeignRekey = false
	effective.MaxFeeMicroAlgos = maxFee
	ir.SetPolicyState(stored, effective)

	snapshot := svc.BuildPolicySnapshot(adminproto.PolicyTargetSigner)
	if !snapshot.Success {
		t.Fatalf("BuildPolicySnapshot() success = false, code %q error %q", snapshot.Code, snapshot.Error)
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

	snapshot := svc.BuildPolicySnapshot(adminproto.PolicyTargetSigner)
	if snapshot.Success {
		t.Fatal("BuildPolicySnapshot() success = true, want false without stored snapshot")
	}
	if snapshot.Code != "policy_snapshot_unavailable" {
		t.Fatalf("Code = %q, want policy_snapshot_unavailable", snapshot.Code)
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

	snapshot := svc.BuildPolicySnapshot(adminproto.PolicyTargetSentry)
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
	svc, _, _ := setupAdminServiceWithRole(t, noderole.RoleSigner)
	sentryYAML := sentryPolicyYAMLForAdminTest("allow_validate")
	result := svc.ValidatePolicy(adminproto.ValidatePolicyRequest{
		Target:     adminproto.PolicyTargetSentry,
		PolicyYAML: sentryYAML,
	})
	if result.Success {
		t.Fatalf("ValidatePolicy(sentry on signer) success = true, want false")
	}
	if result.Code != "policy_target_not_allowed_for_node_role" {
		t.Fatalf("Code = %q, want policy_target_not_allowed_for_node_role", result.Code)
	}

	sentrySvc, _, _ := setupAdminServiceWithRole(t, noderole.RoleSentry)
	result = sentrySvc.ValidatePolicy(adminproto.ValidatePolicyRequest{
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
	initialSnapshot := svc.BuildPolicySnapshot(adminproto.PolicyTargetSentry)
	if !initialSnapshot.Success {
		t.Fatalf("initial snapshot success = false, code %q error %q", initialSnapshot.Code, initialSnapshot.Error)
	}

	updatedYAML := sentryPolicyYAMLForAdminTest("allow_updated")
	result := svc.ReplacePolicy(adminproto.ReplacePolicyRequest{
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
	err := ir.WithKeyring(func(masterKey *securecrypto.Keyring) error {
		var err error
		verified, err = policy.LoadVerifiedSentryConfigWithKeyring(svc.Deps.DataDir(), masterKey)
		return err
	})
	if err != nil {
		t.Fatalf("LoadVerifiedSentryConfigWithKeyring(): %v", err)
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
	svc, _, _ := setupAdminServiceWithRole(t, noderole.RoleSentry)
	result := svc.ReplacePolicy(adminproto.ReplacePolicyRequest{
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
