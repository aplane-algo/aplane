// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func TestBuildAdminSettings_PassphraseMethod(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}

	// No unlock config → "none"
	settings := svc.BuildAdminSettings(ir)
	if settings.PassphraseMethod != "none" {
		t.Errorf("no config: got PassphraseMethod %q, want %q", settings.PassphraseMethod, "none")
	}

	// Write identity-scoped passfile config
	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(server.dataDir, auth.DefaultIdentityID, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	// Should now report "passfile"
	settings = svc.BuildAdminSettings(ir)
	if settings.PassphraseMethod != "passfile" {
		t.Errorf("after appass set passfile: got PassphraseMethod %q, want %q", settings.PassphraseMethod, "passfile")
	}
}

func TestBuildAdminSettings_TimeoutZeroInHeadlessMode(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	// Simulate the default config: 15m admin idle timeout, lock_on_disconnect true
	ir.Config().SetSessionTimeout(15 * time.Minute)
	ir.Config().SetLockOnDisconnect(true)

	svc := signerAdminServices{signer: server}

	// Without passfile: settings should reflect identity config
	settings := svc.BuildAdminSettings(ir)
	if settings.PassphraseTimeout != "15m0s" {
		t.Errorf("prompt mode: got PassphraseTimeout %q, want %q", settings.PassphraseTimeout, "15m0s")
	}
	if !settings.LockOnDisconnect {
		t.Errorf("prompt mode: got LockOnDisconnect false, want true")
	}

	// Enable passfile via unlock.yaml
	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(server.dataDir, auth.DefaultIdentityID, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	// With passfile: headless overrides must apply
	settings = svc.BuildAdminSettings(ir)
	if settings.PassphraseTimeout != "0" {
		t.Errorf("headless mode: got PassphraseTimeout %q, want %q", settings.PassphraseTimeout, "0")
	}
	if settings.LockOnDisconnect {
		t.Errorf("headless mode: got LockOnDisconnect true, want false")
	}
	if settings.PassphraseMethod != "passfile" {
		t.Errorf("headless mode: got PassphraseMethod %q, want %q", settings.PassphraseMethod, "passfile")
	}
}

func TestUpdateAdminSetting_RejectsLockOnDisconnectInHeadlessMode(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// Write config.yaml so the external-change check passes
	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	// Enable identity-scoped passfile (headless mode)
	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(server.dataDir, auth.DefaultIdentityID, unlockCfg); err != nil {
		t.Fatal(err)
	}

	svc := signerAdminServices{signer: server}

	// Attempting to enable lock_on_disconnect in headless mode must fail
	err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingLockOnDisconnect,
		Value: "true",
	})
	if err == nil {
		t.Fatal("UpdateAdminSetting(lock_on_disconnect=true) should fail in headless mode")
	}
	if !strings.Contains(err.Error(), "headless mode") {
		t.Fatalf("error should mention headless mode, got: %v", err)
	}

	// Setting lock_on_disconnect=false should still succeed
	err = svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingLockOnDisconnect,
		Value: "false",
	})
	if err != nil {
		t.Fatalf("UpdateAdminSetting(lock_on_disconnect=false) should succeed in headless mode: %v", err)
	}
}

func TestUpdateAdminSetting_RejectsPassphraseTimeoutInHeadlessMode(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	// Enable identity-scoped passfile (headless mode)
	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(server.dataDir, auth.DefaultIdentityID, unlockCfg); err != nil {
		t.Fatal(err)
	}

	svc := signerAdminServices{signer: server}

	// Attempting to set a non-zero timeout in headless mode must fail
	err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingPassphraseTimeout,
		Value: "15m",
	})
	if err == nil {
		t.Fatal("UpdateAdminSetting(passphrase_timeout=15m) should fail in headless mode")
	}
	if !strings.Contains(err.Error(), "headless mode") {
		t.Fatalf("error should mention headless mode, got: %v", err)
	}

	// Setting timeout to "0" (disabled) should still succeed
	err = svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   adminproto.AdminSettingPassphraseTimeout,
		Value: "0",
	})
	if err != nil {
		t.Fatalf("UpdateAdminSetting(passphrase_timeout=0) should succeed in headless mode: %v", err)
	}
}

func TestUpdateAdminSettingModeIsReadOnly(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	err := (signerAdminServices{signer: server}).UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
		Key:   "mode",
		Value: "sentry",
	})
	if err == nil {
		t.Fatal("UpdateAdminSetting(mode) error = nil")
	}
	if !strings.Contains(err.Error(), "unknown or read-only setting") {
		t.Fatalf("error = %q, want read-only", err.Error())
	}
}

func TestConcurrentProcessConfigUpdatesAreSerialized(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}

	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			values := []string{"dark", "light", "auto"}
			for i := 0; i < 10; i++ {
				if err := svc.UpdateAdminSetting(ir, adminproto.UpdateAdminSettingRequest{
					Key:   adminproto.AdminSettingTheme,
					Value: values[(worker+i)%len(values)],
				}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("UpdateAdminSetting(theme) error = %v", err)
		}
	}

	disk, err := serverconfig.LoadServerConfig(server.dataDir)
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if disk.Theme != server.Theme() {
		t.Fatalf("disk Theme = %q, in-memory Theme = %q", disk.Theme, server.Theme())
	}
	switch disk.Theme {
	case "auto", "dark", "light":
	default:
		t.Fatalf("disk Theme = %q, want valid theme", disk.Theme)
	}
}

func TestConcurrentIdentityConfigUpdatesAreIdentityScoped(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	defaultIR := server.registry.Get(auth.DefaultIdentityID)
	if defaultIR == nil {
		t.Fatal("expected default identity runtime")
	}
	aliceIR := registerAdditionalAdminTestIdentity(t, server, "alice")
	svc := signerAdminServices{signer: server}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		ir        *identity.Runtime
		finalWant bool
	}{
		{ir: defaultIR, finalWant: true},
		{ir: aliceIR, finalWant: false},
	} {
		tc := tc
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 20; i++ {
				value := !tc.finalWant
				if i == 19 {
					value = tc.finalWant
				}
				if err := svc.UpdateAdminSetting(tc.ir, adminproto.UpdateAdminSettingRequest{
					Key:   adminproto.AdminSettingUserAutoApprove,
					Value: boolString(value),
				}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("UpdateAdminSetting(user_auto_approve) error = %v", err)
		}
	}

	defaultStored, err := identity.LoadStoredConfig(server.dataDir, defaultIR.ID())
	if err != nil {
		t.Fatalf("LoadStoredConfig(default) error = %v", err)
	}
	aliceStored, err := identity.LoadStoredConfig(server.dataDir, aliceIR.ID())
	if err != nil {
		t.Fatalf("LoadStoredConfig(alice) error = %v", err)
	}
	if defaultStored.UserAutoApprove == nil || *defaultStored.UserAutoApprove != true {
		t.Fatalf("default UserAutoApprove = %+v, want true", defaultStored.UserAutoApprove)
	}
	if aliceStored.UserAutoApprove == nil || *aliceStored.UserAutoApprove != false {
		t.Fatalf("alice UserAutoApprove = %+v, want false", aliceStored.UserAutoApprove)
	}
	if !defaultIR.Config().UserAutoApprove() {
		t.Fatal("default runtime UserAutoApprove = false, want true")
	}
	if aliceIR.Config().UserAutoApprove() {
		t.Fatal("alice runtime UserAutoApprove = true, want false")
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestReplacePolicy_PersistsUploadedBytesAndApplies(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	uploaded := "reject_foreign_rekey: false\nmax_fee_microalgos: 4321\nalways_review_warnings: true\n"
	result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{PolicyYAML: uploaded})
	if !result.Success {
		t.Fatalf("ReplacePolicy() success = false, code %q error %q", result.Code, result.Error)
	}
	if !result.Canonical || result.PolicySHA256 == "" {
		t.Fatalf("ReplacePolicy() result = %+v, want canonical snapshot with SHA", result)
	}
	if !strings.Contains(result.PolicyYAML, "reject_foreign_rekey: false") ||
		!strings.Contains(result.PolicyYAML, "max_fee_microalgos: 4321") {
		t.Fatalf("canonical policy missing uploaded settings:\n%s", result.PolicyYAML)
	}

	onDisk, err := os.ReadFile(policy.PolicyPath(server.dataDir, auth.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy.yaml) error = %v", err)
	}
	if string(onDisk) != uploaded {
		t.Fatalf("policy.yaml = %q, want exact uploaded bytes %q", string(onDisk), uploaded)
	}

	got := ir.Policy()
	if got == nil {
		t.Fatal("Policy() = nil")
		return
	}
	if got.RejectForeignRekey {
		t.Fatal("RejectForeignRekey = true, want false")
	}
	if got.MaxFeeMicroAlgos != 4321 {
		t.Fatalf("MaxFeeMicroAlgos = %d, want 4321", got.MaxFeeMicroAlgos)
	}
	if !got.AlwaysReviewWarnings {
		t.Fatal("AlwaysReviewWarnings = false, want true")
	}
	assertPolicySidecarVerifies(t, ir, server.dataDir)
}

func TestReplacePolicy_RejectsInvalidPolicyWithoutOverwrite(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	baseline := "reject_foreign_rekey: false\nmax_fee_microalgos: 4321\n"
	if result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{PolicyYAML: baseline}); !result.Success {
		t.Fatalf("ReplacePolicy(baseline) success = false, code %q error %q", result.Code, result.Error)
	}

	invalid := "max_asa_amounts:\n  testnet:\n    usdc: 1\n"
	result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{PolicyYAML: invalid})
	if result.Success {
		t.Fatal("ReplacePolicy(invalid) success = true, want false")
	}
	if result.Code != "policy_validation_failed" {
		t.Fatalf("ReplacePolicy(invalid) code = %q, want policy_validation_failed; error %q", result.Code, result.Error)
	}
	onDisk, err := os.ReadFile(policy.PolicyPath(server.dataDir, auth.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy.yaml) error = %v", err)
	}
	if string(onDisk) != baseline {
		t.Fatalf("policy.yaml changed to %q, want baseline %q", string(onDisk), baseline)
	}
	if got := ir.Policy(); got == nil || got.MaxFeeMicroAlgos != 4321 || got.RejectForeignRekey {
		t.Fatalf("Policy() = %+v, want unchanged baseline", got)
	}
	assertPolicySidecarVerifies(t, ir, server.dataDir)
}

func TestReplacePolicy_RejectsStaleExpectedSnapshot(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	baseline := "max_fee_microalgos: 4321\n"
	if result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{PolicyYAML: baseline}); !result.Success {
		t.Fatalf("ReplacePolicy(baseline) success = false, code %q error %q", result.Code, result.Error)
	}

	result := svc.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{
		PolicyYAML:            "max_fee_microalgos: 9999\n",
		ExpectedCurrentSHA256: "deadbeef",
	})
	if result.Success {
		t.Fatal("ReplacePolicy(stale) success = true, want false")
	}
	if result.Code != "policy_snapshot_changed" {
		t.Fatalf("ReplacePolicy(stale) code = %q, want policy_snapshot_changed; error %q", result.Code, result.Error)
	}
	onDisk, err := os.ReadFile(policy.PolicyPath(server.dataDir, auth.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy.yaml) error = %v", err)
	}
	if string(onDisk) != baseline {
		t.Fatalf("policy.yaml changed to %q, want baseline %q", string(onDisk), baseline)
	}
	if got := ir.Policy(); got == nil || got.MaxFeeMicroAlgos != 4321 {
		t.Fatalf("Policy() = %+v, want unchanged baseline", got)
	}
}

func TestReplacePolicyFailsWhenLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	ir.Lock()

	result := signerAdminServices{signer: server}.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{
		PolicyYAML: "max_fee_microalgos: 4321\n",
	})
	if result.Success {
		t.Fatal("ReplacePolicy() success = true, want locked identity failure")
	}
	if result.Code != "identity_locked" || !strings.Contains(result.Error, "unlock signer before replacing policy") {
		t.Fatalf("ReplacePolicy() result = %+v, want identity_locked message", result)
	}
}

func assertPolicySidecarVerifies(t *testing.T, ir *identity.Runtime, dataDir string) {
	t.Helper()
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		_, err := policy.LoadVerifiedStoredConfigWithKeyring(dataDir, ir.ID(), keyringForTest(t, masterKey))
		return err
	}); err != nil {
		t.Fatalf("policy sidecar did not verify: %v", err)
	}
}

// keyringForTest wraps a raw term-1 key as a keyring, matching what the store
// holds while phase 2 migrates callers from raw keys to the keyring.
func keyringForTest(t *testing.T, masterKey []byte) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyringFromKey(masterKey)
	if err != nil {
		t.Fatalf("NewKeyringFromKey(): %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}
