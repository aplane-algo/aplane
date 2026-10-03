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
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
)

func activeDaemonPolicyPath(t *testing.T, server *Signer) string {
	t.Helper()
	active, err := server.productRuntime().ActivePaths()
	if err != nil {
		t.Fatalf("ActivePaths() error = %v", err)
	}
	return active.PolicyPath()
}

func TestBuildAdminSettings_PassphraseMethod(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	svc := server.adminServices()

	// No unlock config → "none"
	settings := svc.adminApp().BuildAdminSettings()
	if settings.PassphraseMethod != "none" {
		t.Errorf("no config: got PassphraseMethod %q, want %q", settings.PassphraseMethod, "none")
	}

	// Write product-store passfile config
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(server.dataDir, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	// Should now report "passfile"
	settings = svc.adminApp().BuildAdminSettings()
	if settings.PassphraseMethod != "passfile" {
		t.Errorf("after selecting Passfile in appass: got PassphraseMethod %q, want %q", settings.PassphraseMethod, "passfile")
	}
}

func TestChangeStorePassphraseCompletesRotationAndRepublishesRuntime(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	convertTestSignerToGenerational(t, server)
	newPassphrase := []byte("new-admin-passphrase")

	result := server.adminServices().ChangeStorePassphrase(
		adminproto.ChangeStorePassphraseRequest{
			CurrentPassphrase: testPassphrase,
			NewPassphrase:     newPassphrase,
		},
	)
	if !result.Success {
		t.Fatalf("ChangeStorePassphrase() = %+v", result)
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf(
			"product-store state = unlocked %v recovery %v, want ordinary unlocked",
			ir.IsUnlocked(),
			ir.IsRecovery(),
		)
	}
	if err := crypto.VerifyPassphraseWithStoreRoot(
		newPassphrase,
		server.keyPaths.KeystoreMetadataDir(),
	); err != nil {
		t.Fatalf("new passphrase does not open rotated root: %v", err)
	}
	if err := crypto.VerifyPassphraseWithStoreRoot(
		testPassphrase,
		server.keyPaths.KeystoreMetadataDir(),
	); err == nil {
		t.Fatal("old passphrase still opens rotated root")
	}
}

func TestChangeStorePassphraseFailureLeavesRuntimeLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	convertTestSignerToGenerational(t, server)
	if err := os.WriteFile(server.keyPaths.NodeRolePath(), []byte("role: cosigner\n"), 0o600); err != nil {
		t.Fatalf("tamper node role: %v", err)
	}

	result := server.adminServices().ChangeStorePassphrase(
		adminproto.ChangeStorePassphraseRequest{
			CurrentPassphrase: testPassphrase,
			NewPassphrase:     []byte("new-failing-passphrase"),
		},
	)
	if result.Success {
		t.Fatalf("ChangeStorePassphrase() = %+v, want failure", result)
	}
	if ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf(
			"product-store state = unlocked %v recovery %v, want locked",
			ir.IsUnlocked(),
			ir.IsRecovery(),
		)
	}
}

func TestBuildAdminSettings_TimeoutZeroInHeadlessMode(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	// Simulate the default config: 15m admin idle timeout, lock_on_disconnect true
	ir.Config().SetSessionTimeout(15 * time.Minute)
	ir.Config().SetLockOnDisconnect(true)

	svc := server.adminServices()

	// Without passfile: settings should reflect product runtime config
	settings := svc.adminApp().BuildAdminSettings()
	if settings.PassphraseTimeout != "15m0s" {
		t.Errorf("prompt mode: got PassphraseTimeout %q, want %q", settings.PassphraseTimeout, "15m0s")
	}
	if !settings.LockOnDisconnect {
		t.Errorf("prompt mode: got LockOnDisconnect false, want true")
	}

	// Enable passfile via unlock.yaml
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(server.dataDir, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig: %v", err)
	}

	// With passfile: headless overrides must apply
	settings = svc.adminApp().BuildAdminSettings()
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

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	// Enable product-store passfile (headless mode)
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(server.dataDir, unlockCfg); err != nil {
		t.Fatal(err)
	}

	svc := server.adminServices()

	// Attempting to enable lock_on_disconnect in headless mode must fail
	err := svc.adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
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
	err = svc.adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
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

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	// Enable product-store passfile (headless mode)
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(server.dataDir, unlockCfg); err != nil {
		t.Fatal(err)
	}

	svc := server.adminServices()

	// Attempting to set a non-zero timeout in headless mode must fail
	err := svc.adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
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
	err = svc.adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
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

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	err := server.adminServices().adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
		Key:   "mode",
		Value: "cosigner",
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

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()

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
				if err := svc.adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
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

func TestConcurrentProductConfigUpdatesAreSerialized(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	productRuntime := server.productRuntime()
	if productRuntime == nil {
		t.Fatal("expected product runtime")
	}
	svc := server.adminServices()

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		key   string
		value string
	}{
		{key: adminproto.AdminSettingUserAutoApprove, value: "true"},
		{key: adminproto.AdminSettingLockOnDisconnect, value: "false"},
	} {
		tc := tc
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 20; i++ {
				if err := svc.adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
					Key:   tc.key,
					Value: tc.value,
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

	stored, err := productruntime.LoadStoredConfig(server.dataDir)
	if err != nil {
		t.Fatalf("LoadStoredConfig(product) error = %v", err)
	}
	if stored.UserAutoApprove == nil || !*stored.UserAutoApprove {
		t.Fatalf("product UserAutoApprove = %+v, want true", stored.UserAutoApprove)
	}
	if stored.LockOnDisconnect == nil || *stored.LockOnDisconnect {
		t.Fatalf("product LockOnDisconnect = %+v, want false", stored.LockOnDisconnect)
	}
	if !productRuntime.Config().UserAutoApprove() || productRuntime.Config().LockOnDisconnect() {
		t.Fatal("runtime did not retain both concurrent product settings")
	}
}

func TestApplyPolicy_PersistsUploadedBytesAndReloads(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	svc := server.adminServices()
	current := svc.adminApp().GetPolicy()
	if !current.Success {
		t.Fatalf("GetPolicy() = %+v", current)
	}
	uploaded := "{\n  \"format\": \"aplane.signer-policy.v1\",\n  \"reject_foreign_rekey\": false,\n" +
		"  \"max_fee_microalgos\": \"4321\",\n  \"always_review_warnings\": true\n}\n"
	result := svc.adminApp().ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Document: uploaded}},
		ExpectedPolicySetSHA256: current.PolicySetSHA256,
	})
	if !result.Success || result.Policy == nil || result.Policy.GenerationID == "" {
		t.Fatalf("ApplyPolicy() = %+v", result)
	}
	if doc := svc.adminApp().GetPolicyDocument(""); !doc.Success || doc.Document != uploaded {
		t.Fatalf("GetPolicyDocument() = %+v, want the exact uploaded bytes", doc)
	}

	onDisk, err := os.ReadFile(activeDaemonPolicyPath(t, server))
	if err != nil {
		t.Fatalf("ReadFile(policy.json) error = %v", err)
	}
	if string(onDisk) != uploaded {
		t.Fatalf("policy.json = %q, want exact uploaded bytes %q", string(onDisk), uploaded)
	}

	got := ir.Policy()
	if got == nil {
		t.Fatal("Policy() = nil")
		return
	}
	if got.RejectForeignRekey || got.MaxFeeMicroAlgos != 4321 || !got.AlwaysReviewWarnings {
		t.Fatalf("Policy() = %+v, want the uploaded settings", got)
	}
	assertPolicySidecarVerifies(t, ir)
}

// applySignerPolicyDoc applies one signer document against the current
// policy and returns the result.
func applySignerPolicyDoc(t *testing.T, server *Signer, doc string) adminproto.ApplyPolicyResult {
	t.Helper()
	current := server.adminServices().adminApp().GetPolicy()
	return server.adminServices().adminApp().ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Document: doc}},
		ExpectedPolicySetSHA256: current.PolicySetSHA256,
	})
}

func TestApplyPolicy_RejectsInvalidPolicyWithoutOverwrite(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	baseline := `{"format":"aplane.signer-policy.v1","reject_foreign_rekey":false,"max_fee_microalgos":"4321"}`
	if result := applySignerPolicyDoc(t, server, baseline); !result.Success {
		t.Fatalf("ApplyPolicy(baseline) = %+v", result)
	}

	invalid := `{"format":"aplane.signer-policy.v1","limits":{"testnet":{"usdc":{"reject_above":"1"}}}}`
	result := applySignerPolicyDoc(t, server, invalid)
	if result.Success || result.Code != "policy_validation_failed" || len(result.Errors) != 1 {
		t.Fatalf("ApplyPolicy(invalid) = %+v, want one policy_validation_failed problem", result)
	}
	onDisk, err := os.ReadFile(activeDaemonPolicyPath(t, server))
	if err != nil {
		t.Fatalf("ReadFile(policy.json) error = %v", err)
	}
	if string(onDisk) != baseline {
		t.Fatalf("policy.json changed to %q, want baseline %q", string(onDisk), baseline)
	}
	if got := ir.Policy(); got == nil || got.MaxFeeMicroAlgos != 4321 || got.RejectForeignRekey {
		t.Fatalf("Policy() = %+v, want unchanged baseline", got)
	}
	assertPolicySidecarVerifies(t, ir)
}

func TestApplyPolicy_RejectsStaleExpectedSnapshot(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	baseline := `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"4321"}`
	if result := applySignerPolicyDoc(t, server, baseline); !result.Success {
		t.Fatalf("ApplyPolicy(baseline) = %+v", result)
	}

	result := server.adminServices().adminApp().ApplyPolicy(adminproto.ApplyPolicyRequest{
		Documents:               []adminproto.PolicyDocument{{Document: `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"9999"}`}},
		ExpectedPolicySetSHA256: "deadbeef",
	})
	if result.Success || result.Code != "policy_snapshot_changed" {
		t.Fatalf("ApplyPolicy(stale) = %+v, want policy_snapshot_changed", result)
	}
	onDisk, err := os.ReadFile(activeDaemonPolicyPath(t, server))
	if err != nil {
		t.Fatalf("ReadFile(policy.json) error = %v", err)
	}
	if string(onDisk) != baseline {
		t.Fatalf("policy.json changed to %q, want baseline %q", string(onDisk), baseline)
	}
	if got := ir.Policy(); got == nil || got.MaxFeeMicroAlgos != 4321 {
		t.Fatalf("Policy() = %+v, want unchanged baseline", got)
	}
}

func TestApplyPolicyFailsWhenLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	ir.Lock()

	result := applySignerPolicyDoc(t, server, `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"4321"}`)
	if result.Success || result.Code != "identity_locked" || !strings.Contains(result.Error, "unlock the signer before applying policy") {
		t.Fatalf("ApplyPolicy() = %+v, want identity_locked", result)
	}
}

func assertPolicySidecarVerifies(t *testing.T, ir *productruntime.Runtime) {
	t.Helper()
	if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		active, err := ir.ActivePaths()
		if err != nil {
			return err
		}
		_, _, err = policy.LoadVerifiedSignerPolicy(active, masterKey)
		return err
	}); err != nil {
		t.Fatalf("policy sidecar did not verify: %v", err)
	}
}
