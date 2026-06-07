// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
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
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
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
		Value: "attestation",
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

	disk, err := apconfig.LoadServerConfig(server.dataDir)
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

func TestBuildPolicySettings_UsesRuntimePolicy(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	ir.SetPolicy(&policy.Config{
		RejectForeignRekey:          true,
		RejectCloseRemainder:        false,
		AlwaysReviewWarnings:        true,
		AutoApproveSelfNoOpTransfer: true,
		MaxFeeMicroAlgos:            1000,
		ReviewAlgoPayments: map[string]uint64{
			"testnet":     5_250_000,
			"voi_mainnet": 1_000_000,
		},
		MaxAlgoPayments: map[string]uint64{
			"testnet":     10_500_000,
			"voi_mainnet": 2_000_000,
		},
		ReviewASAAmounts: map[string]map[uint64]uint64{
			"testnet": {
				123: 10,
			},
			"voi_mainnet": {
				42: 3,
			},
		},
		MaxASAAmounts: map[string]map[uint64]uint64{
			"testnet": {
				123: 45,
				9:   1,
			},
			"mainnet": {
				31566704: 5000,
			},
			"voi_mainnet": {
				42: 7,
			},
		},
	})
	server.config.Algod = apconfig.AlgodConfig{
		"mainnet":     &apconfig.AlgodNetworkConfig{Server: "http://mainnet-algod"},
		"testnet":     &apconfig.AlgodNetworkConfig{Server: "http://testnet-algod"},
		"voi_mainnet": &apconfig.AlgodNetworkConfig{Server: "http://voi-algod"},
		"no_server":   &apconfig.AlgodNetworkConfig{},
	}

	settings := signerAdminServices{signer: server}.BuildPolicySettings(ir)
	if !settings.RejectForeignRekey {
		t.Fatal("RejectForeignRekey = false, want true")
	}
	if settings.RejectCloseRemainder {
		t.Fatal("RejectCloseRemainder = true, want false")
	}
	if !settings.AlwaysReviewWarnings {
		t.Fatal("AlwaysReviewWarnings = false, want true")
	}
	if !settings.AutoApproveSelfNoOpTransfer {
		t.Fatal("AutoApproveSelfNoOpTransfer = false, want true")
	}
	if settings.MaxFeeMicroAlgos != "1000" {
		t.Fatalf("MaxFeeMicroAlgos = %q, want 1000", settings.MaxFeeMicroAlgos)
	}
	if settings.MaxAlgoPayments["testnet"] != "10.5" {
		t.Fatalf("MaxAlgoPayments[testnet] = %q, want 10.5", settings.MaxAlgoPayments["testnet"])
	}
	if settings.ReviewAlgoPayments["testnet"] != "5.25" {
		t.Fatalf("ReviewAlgoPayments[testnet] = %q, want 5.25", settings.ReviewAlgoPayments["testnet"])
	}
	if settings.MaxAlgoPayments["voi_mainnet"] != "2" {
		t.Fatalf("MaxAlgoPayments[voi_mainnet] = %q, want 2", settings.MaxAlgoPayments["voi_mainnet"])
	}
	if settings.ReviewAlgoPayments["voi_mainnet"] != "1" {
		t.Fatalf("ReviewAlgoPayments[voi_mainnet] = %q, want 1", settings.ReviewAlgoPayments["voi_mainnet"])
	}
	if got, want := strings.Join(settings.PolicyNetworks, ","), "mainnet,testnet,voi_mainnet"; got != want {
		t.Fatalf("PolicyNetworks = %q, want %q", got, want)
	}
	if settings.MaxASAAmountsTestnet != "9:1, 123:45" {
		t.Fatalf("MaxASAAmountsTestnet = %q, want %q", settings.MaxASAAmountsTestnet, "9:1, 123:45")
	}
	if settings.MaxASAAmountsMainnet != "31566704:0.005" {
		t.Fatalf("MaxASAAmountsMainnet = %q, want %q", settings.MaxASAAmountsMainnet, "31566704:0.005")
	}
	if settings.MaxASAAmounts["voi_mainnet"] != "42:7" {
		t.Fatalf("MaxASAAmounts[voi_mainnet] = %q, want %q", settings.MaxASAAmounts["voi_mainnet"], "42:7")
	}
	if settings.ReviewASAAmounts["testnet"] != "123:10" {
		t.Fatalf("ReviewASAAmounts[testnet] = %q, want %q", settings.ReviewASAAmounts["testnet"], "123:10")
	}
	if settings.ReviewASAAmounts["voi_mainnet"] != "42:3" {
		t.Fatalf("ReviewASAAmounts[voi_mainnet] = %q, want %q", settings.ReviewASAAmounts["voi_mainnet"], "42:3")
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestUpdatePolicySetting_PersistsAndApplies(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	server.config.Algod = apconfig.AlgodConfig{
		"mainnet": &apconfig.AlgodNetworkConfig{Server: "http://mainnet-algod"},
		"testnet": &apconfig.AlgodNetworkConfig{Server: "http://testnet-algod"},
	}
	seedSignerASAMetadata(t, server.dataDir, "testnet", asa.Metadata{
		AssetID:  753507995,
		Name:     "Custom Test Asset",
		UnitName: "CTA",
		Decimals: 6,
	})
	for _, tc := range []adminproto.UpdatePolicySettingRequest{
		{Key: adminproto.PolicySettingRejectForeignRekey, Value: "false"},
		{Key: adminproto.PolicySettingAlwaysReviewWarnings, Value: "true"},
		{Key: adminproto.PolicySettingAutoApproveSelfNoOpTransfer, Value: "true"},
		{Key: adminproto.PolicySettingMaxFeeMicroAlgos, Value: "1234"},
	} {
		msg := tc
		if err := svc.UpdatePolicySetting(ir, msg); err != nil {
			t.Fatalf("UpdatePolicySetting(%s) error = %v", msg.Key, err)
		}
	}
	if err := svc.UpdatePolicyASAAmounts(ir, adminproto.UpdatePolicyASAAmountsRequest{
		ReviewAlgoPayments: map[string]string{"mainnet": "1", "testnet": "5"},
		MaxAlgoPayments:    map[string]string{"mainnet": "1.5", "testnet": "10.5"},
		ReviewASAAmounts:   map[string]string{"mainnet": "31566704:4", "testnet": "10458941:7, 753507995:1"},
		Mainnet:            "31566704:8",
		Testnet:            "10458941:77, 753507995:5",
		Betanet:            "",
	}); err != nil {
		t.Fatalf("UpdatePolicyASAAmounts() error = %v", err)
	}

	got := ir.Policy()
	if got == nil {
		t.Fatal("Policy() = nil")
		return
	}
	if got.RejectForeignRekey {
		t.Fatal("RejectForeignRekey = true, want false")
	}
	if got.MaxFeeMicroAlgos != 1234 {
		t.Fatalf("MaxFeeMicroAlgos = %d, want 1234", got.MaxFeeMicroAlgos)
	}
	if !got.AlwaysReviewWarnings {
		t.Fatal("AlwaysReviewWarnings = false, want true")
	}
	if !got.AutoApproveSelfNoOpTransfer {
		t.Fatal("AutoApproveSelfNoOpTransfer = false, want true")
	}
	if got.MaxAlgoPayments["testnet"] != 10_500_000 {
		t.Fatalf("MaxAlgoPayments[testnet] = %d, want 10500000", got.MaxAlgoPayments["testnet"])
	}
	if got.MaxAlgoPayments["mainnet"] != 1_500_000 {
		t.Fatalf("MaxAlgoPayments[mainnet] = %d, want 1500000", got.MaxAlgoPayments["mainnet"])
	}
	if got.ReviewAlgoPayments["testnet"] != 5_000_000 {
		t.Fatalf("ReviewAlgoPayments[testnet] = %d, want 5000000", got.ReviewAlgoPayments["testnet"])
	}
	if got.ReviewAlgoPayments["mainnet"] != 1_000_000 {
		t.Fatalf("ReviewAlgoPayments[mainnet] = %d, want 1000000", got.ReviewAlgoPayments["mainnet"])
	}
	if got.MaxASAAmounts["testnet"][10458941] != 77_000_000 || got.MaxASAAmounts["testnet"][753507995] != 5_000_000 {
		t.Fatalf("MaxASAAmounts = %+v, want persisted values", got.MaxASAAmounts)
	}
	if got.ReviewASAAmounts["testnet"][10458941] != 7_000_000 || got.ReviewASAAmounts["testnet"][753507995] != 1_000_000 {
		t.Fatalf("ReviewASAAmounts = %+v, want persisted values", got.ReviewASAAmounts)
	}
	if got.MaxASAAmounts["mainnet"][31566704] != 8_000_000 {
		t.Fatalf("MaxASAAmounts = %+v, want mainnet persisted values", got.MaxASAAmounts)
	}
	if got.ReviewASAAmounts["mainnet"][31566704] != 4_000_000 {
		t.Fatalf("ReviewASAAmounts = %+v, want mainnet persisted values", got.ReviewASAAmounts)
	}

	stored, err := policy.LoadStoredConfig(server.dataDir, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("LoadStoredConfig() error = %v", err)
	}
	if stored.RejectForeignRekey == nil || *stored.RejectForeignRekey {
		t.Fatalf("stored RejectForeignRekey = %+v, want false", stored.RejectForeignRekey)
	}
	if stored.MaxFeeMicroAlgos == nil || *stored.MaxFeeMicroAlgos != 1234 {
		t.Fatalf("stored MaxFeeMicroAlgos = %+v, want 1234", stored.MaxFeeMicroAlgos)
	}
	if stored.AlwaysReviewWarnings == nil || !*stored.AlwaysReviewWarnings {
		t.Fatalf("stored AlwaysReviewWarnings = %+v, want true", stored.AlwaysReviewWarnings)
	}
	if stored.AutoApproveSelfNoOpTransfer == nil || !*stored.AutoApproveSelfNoOpTransfer {
		t.Fatalf("stored AutoApproveSelfNoOpTransfer = %+v, want true", stored.AutoApproveSelfNoOpTransfer)
	}
	if stored.MaxAlgoPayments["testnet"] != 10_500_000 {
		t.Fatalf("stored MaxAlgoPayments[testnet] = %d, want 10500000", stored.MaxAlgoPayments["testnet"])
	}
	if stored.MaxAlgoPayments["mainnet"] != 1_500_000 {
		t.Fatalf("stored MaxAlgoPayments[mainnet] = %d, want 1500000", stored.MaxAlgoPayments["mainnet"])
	}
	if stored.ReviewAlgoPayments["testnet"] != 5_000_000 {
		t.Fatalf("stored ReviewAlgoPayments[testnet] = %d, want 5000000", stored.ReviewAlgoPayments["testnet"])
	}
	if stored.ReviewAlgoPayments["mainnet"] != 1_000_000 {
		t.Fatalf("stored ReviewAlgoPayments[mainnet] = %d, want 1000000", stored.ReviewAlgoPayments["mainnet"])
	}
	if stored.MaxASAAmounts["testnet"]["10458941"] != 77_000_000 || stored.MaxASAAmounts["testnet"]["753507995"] != 5_000_000 {
		t.Fatalf("stored MaxASAAmounts = %+v, want persisted values", stored.MaxASAAmounts)
	}
	if stored.ReviewASAAmounts["testnet"]["10458941"] != 7_000_000 || stored.ReviewASAAmounts["testnet"]["753507995"] != 1_000_000 {
		t.Fatalf("stored ReviewASAAmounts = %+v, want persisted values", stored.ReviewASAAmounts)
	}
	if stored.MaxASAAmounts["mainnet"]["31566704"] != 8_000_000 {
		t.Fatalf("stored MaxASAAmounts = %+v, want mainnet persisted values", stored.MaxASAAmounts)
	}
	if stored.ReviewASAAmounts["mainnet"]["31566704"] != 4_000_000 {
		t.Fatalf("stored ReviewASAAmounts = %+v, want mainnet persisted values", stored.ReviewASAAmounts)
	}
	assertPolicySidecarVerifies(t, ir, server.dataDir)
}

func TestUpdatePolicySettingFailsWhenLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	ir.Lock()

	err := signerAdminServices{signer: server}.UpdatePolicySetting(ir, adminproto.UpdatePolicySettingRequest{
		Key:   adminproto.PolicySettingRejectForeignRekey,
		Value: "false",
	})
	if err == nil {
		t.Fatal("UpdatePolicySetting() error = nil, want locked identity failure")
	}
	if !strings.Contains(err.Error(), "unlock signer before editing policy") {
		t.Fatalf("UpdatePolicySetting() error = %v, want locked identity message", err)
	}
}

func TestUpdatePolicyASAAmounts_RejectsInvalidASAAmounts(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	err := signerAdminServices{signer: server}.UpdatePolicyASAAmounts(ir, adminproto.UpdatePolicyASAAmountsRequest{
		Testnet: "123:5",
	})
	if err == nil {
		t.Fatal("UpdatePolicyASAAmounts() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("error = %v, want unconfigured network error", err)
	}

	server.config.Algod = apconfig.AlgodConfig{"testnet": &apconfig.AlgodNetworkConfig{Server: "http://testnet-algod"}}
	err = signerAdminServices{signer: server}.UpdatePolicyASAAmounts(ir, adminproto.UpdatePolicyASAAmountsRequest{
		Testnet: "USDC:5",
	})
	if err == nil {
		t.Fatal("UpdatePolicyASAAmounts(symbol) error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "asset id must be numeric") {
		t.Fatalf("error = %v, want numeric asset id error", err)
	}
}

func TestUpdatePolicyASAAmounts_MapRequestPersistsAndRenders(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	server.config.Algod = apconfig.AlgodConfig{
		"testnet": &apconfig.AlgodNetworkConfig{Server: "http://testnet-algod"},
	}
	seedSignerASAMetadata(t, server.dataDir, "testnet", asa.Metadata{
		AssetID:  753507995,
		Name:     "Custom Test Asset",
		UnitName: "CTA",
		Decimals: 6,
	})
	if err := svc.UpdatePolicyASAAmounts(ir, adminproto.UpdatePolicyASAAmountsRequest{
		ReviewASAAmounts: map[string]string{
			"testnet": "10458941:0.5",
		},
		MaxASAAmounts: map[string]string{
			"testnet": "10458941:1, 753507995:1",
		},
	}); err != nil {
		t.Fatalf("UpdatePolicyASAAmounts() error = %v", err)
	}

	stored, err := policy.LoadStoredConfig(server.dataDir, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("LoadStoredConfig() error = %v", err)
	}
	if stored.MaxASAAmounts["testnet"]["10458941"] != 1_000_000 {
		t.Fatalf("stored USDC limit = %d, want 1000000", stored.MaxASAAmounts["testnet"]["10458941"])
	}
	if stored.MaxASAAmounts["testnet"]["753507995"] != 1_000_000 {
		t.Fatalf("stored numeric limit = %d, want 1000000", stored.MaxASAAmounts["testnet"]["753507995"])
	}
	if stored.ReviewASAAmounts["testnet"]["10458941"] != 500_000 {
		t.Fatalf("stored USDC review threshold = %d, want 500000", stored.ReviewASAAmounts["testnet"]["10458941"])
	}

	settings := svc.BuildPolicySettings(ir)
	if got := settings.MaxASAAmounts["testnet"]; got != "10458941:1, 753507995:1" {
		t.Fatalf("MaxASAAmounts[testnet] = %q, want %q", got, "10458941:1, 753507995:1")
	}
	if settings.MaxASAAmountsTestnet != "10458941:1, 753507995:1" {
		t.Fatalf("MaxASAAmountsTestnet = %q, want %q", settings.MaxASAAmountsTestnet, "10458941:1, 753507995:1")
	}
	if got := settings.ReviewASAAmounts["testnet"]; got != "10458941:0.5" {
		t.Fatalf("ReviewASAAmounts[testnet] = %q, want %q", got, "10458941:0.5")
	}
	assertPolicySidecarVerifies(t, ir, server.dataDir)
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
		_, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataDir, ir.ID(), masterKey)
		return err
	}); err != nil {
		t.Fatalf("policy sidecar did not verify: %v", err)
	}
}

func seedSignerASAMetadata(t *testing.T, dataDir, network string, meta asa.Metadata) {
	t.Helper()

	metadataStore := asametadata.NewStore(dataDir)
	if err := metadataStore.SaveLocalMetadata(network, meta); err != nil {
		t.Fatalf("SaveLocalMetadata() error = %v", err)
	}
}
