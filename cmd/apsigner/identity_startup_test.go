// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storeinit"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	util "github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestStartupIdentityIDsIncludesProductIdentity(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(root, "identities", id), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := signerstartup.StartupIdentityIDs(root, auth.CurrentProductIdentityID())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)

	want := []string{"alice", "bob", auth.CurrentProductIdentityID()}
	sort.Strings(want)
	if len(ids) != len(want) {
		t.Fatalf("ids len = %d, want %d (%v)", len(ids), len(want), ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids[%d] = %q, want %q (all=%v)", i, ids[i], want[i], ids)
		}
	}
}

func TestBuildIdentityRuntimeAppliesStoredConfig(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := config.DefaultServerConfig()

	if err := identity.SaveStoredSetting(root, "alice", "user_auto_approve", true); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveStoredSetting(root, "alice", "lock_on_disconnect", false); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveStoredSetting(root, "alice", "passphrase_timeout", "30m"); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveStoredSetting(root, "alice", "approval_wait", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root, "alice"); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err != nil {
		t.Fatal(err)
	}

	if !ir.Config().UserAutoApprove() {
		t.Fatal("user_auto_approve override not applied")
	}
	if ir.Config().LockOnDisconnect() {
		t.Fatal("lock_on_disconnect override not applied")
	}
	if ir.Config().SessionTimeout() != 30*time.Minute {
		t.Fatalf("session timeout = %s, want %s", ir.Config().SessionTimeout(), 30*time.Minute)
	}
	if ir.Config().ApprovalWait() != 10*time.Minute {
		t.Fatalf("approval wait = %s, want %s", ir.Config().ApprovalWait(), 10*time.Minute)
	}
	if got := ir.Policy(); got != nil {
		t.Fatalf("policy = %+v, want nil before unlock verification", got)
	}
}

func TestBuildIdentityRuntimeRejectsStoredMode(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := config.DefaultServerConfig()

	if err := identity.SaveStoredSetting(root, "alice", "mode", "attestation"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root, "alice"); err != nil {
		t.Fatal(err)
	}

	_, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err == nil {
		t.Fatal("BuildIdentityRuntime() error = nil")
	}
	if !strings.Contains(err.Error(), "identity config mode is unsupported") {
		t.Fatalf("BuildIdentityRuntime() error = %q, want unsupported mode", err.Error())
	}
}

func TestStartupIdentityIDsSkipsDecommissionedIdentities(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(root, "identities", id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := identity.SaveStoredSetting(root, "bob", "decommissioned", true); err != nil {
		t.Fatal(err)
	}

	ids, err := signerstartup.StartupIdentityIDs(root, auth.CurrentProductIdentityID())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)

	want := []string{"alice", auth.CurrentProductIdentityID()}
	sort.Strings(want)
	if len(ids) != len(want) {
		t.Fatalf("ids len = %d, want %d (%v)", len(ids), len(want), ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids[%d] = %q, want %q (all=%v)", i, ids[i], want[i], ids)
		}
	}
}

func TestBuildIdentityRuntimeForcesHeadlessOverrides_IdentityScopedPassfile(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
		dataDir:  root,
	}
	cfg := config.DefaultServerConfig()
	// Process-global config has NO passphrase_command_argv, so
	// cfg.ShouldLockOnDisconnect() returns true (the default).

	// Write identity-scoped unlock.yaml (simulates appass set passfile)
	unlockCfg := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := identity.SaveUnlockConfig(root, "alice", unlockCfg); err != nil {
		t.Fatal(err)
	}

	// Also save an explicit lock_on_disconnect=true in the identity stored config
	// to prove the headless override wins over both the default AND stored overrides.
	if err := identity.SaveStoredSetting(root, "alice", "lock_on_disconnect", true); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveStoredSetting(root, "alice", "passphrase_timeout", "30m"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root, "alice"); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err != nil {
		t.Fatal(err)
	}

	if ir.Config().LockOnDisconnect() {
		t.Fatal("lock_on_disconnect must be false when identity has passfile configured")
	}
	if ir.Config().SessionTimeout() != 0 {
		t.Fatalf("admin idle timeout = %s, want 0 (headless mode disables timeout)", ir.Config().SessionTimeout())
	}
}

func TestBuildIdentityRuntimeForcesHeadlessOverrides_GlobalPassfile(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
		dataDir:  root,
	}
	cfg := config.DefaultServerConfig()
	// Process-global passphrase command — ShouldLockOnDisconnect() returns false.
	// But also write a stored override to prove the headless path catches it.
	cfg.PassphraseCommandArgv = []string{"/usr/local/bin/appass-file", "/tmp/secret"}

	if err := identity.SaveStoredSetting(root, "alice", "lock_on_disconnect", true); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveStoredSetting(root, "alice", "passphrase_timeout", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root, "alice"); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err != nil {
		t.Fatal(err)
	}

	if ir.Config().LockOnDisconnect() {
		t.Fatal("lock_on_disconnect must be false when global passfile is configured")
	}
	if ir.Config().SessionTimeout() != 0 {
		t.Fatalf("admin idle timeout = %s, want 0 (headless mode disables timeout)", ir.Config().SessionTimeout())
	}
}

func TestBuildIdentityRuntimeRoutesLockedNotificationByIdentity(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
		dataDir:  root,
	}
	cfg := config.DefaultServerConfig()
	hub := &recordingAdminHub{}

	if _, err := util.LoadAPlaneToken(root, "alice"); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{
		NotifyLocked: func(identityID string) {
			hub.NotifyLocked(identityID, adminproto.SignerLockedNotification{Reason: "locked"})
		},
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}

	ir.SetUnlocked()
	ir.Lock()

	if hub.lockedIdentity != "alice" {
		t.Fatalf("NotifyLocked identity = %q, want alice", hub.lockedIdentity)
	}
}

func TestBuildIdentityRuntimeRejectsSecondaryIdentityWithoutToken(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := config.DefaultServerConfig()

	_, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err == nil {
		t.Fatal("BuildIdentityRuntime() succeeded without token, want error")
	}
	if !strings.Contains(err.Error(), "missing token file") {
		t.Fatalf("BuildIdentityRuntime() error = %v, want missing token file", err)
	}
}

func TestBuildIdentityRuntimeLoadsStoredPolicy(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := config.DefaultServerConfig()
	passphrase := []byte("policy-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir:    root,
		Paths:      server.keyPaths,
		IdentityID: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	maxFee := uint64(1234)
	stored := &policy.StoredConfig{
		RejectForeignRekey: boolPtr(false),
		MaxFeeMicroAlgos:   &maxFee,
		MaxASAAmounts: map[string]map[string]uint64{
			"testnet": {
				"31566704": 77,
			},
		},
	}
	masterKey := testMasterKeyForIdentity(t, server.keyPaths, "alice", passphrase)
	defer crypto.ZeroBytes(masterKey)
	if err := policy.SaveStoredConfigWithMasterKey(root, "alice", stored, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if pol := ir.Policy(); pol != nil {
		t.Fatalf("Policy() before unlock = %+v, want nil", pol)
	}
	if _, err := ir.ReloadWithPassphrase(passphrase); err != nil {
		t.Fatalf("ReloadWithPassphrase() error = %v", err)
	}
	pol := ir.Policy()
	if pol == nil {
		t.Fatal("Policy() = nil")
		return
	}
	if pol.RejectForeignRekey {
		t.Fatal("RejectForeignRekey = true, want false from stored policy")
	}
	if got := pol.MaxFeeMicroAlgos; got != maxFee {
		t.Fatalf("MaxFeeMicroAlgos = %d, want %d", got, maxFee)
	}
	if got := pol.MaxASAAmounts["testnet"][31566704]; got != 77 {
		t.Fatalf("MaxASAAmounts[testnet][31566704] = %d, want 77", got)
	}
}

func TestBuildIdentityRuntimeRejectsUnsignedPolicyOnUnlock(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := config.DefaultServerConfig()
	passphrase := []byte("policy-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir:    root,
		Paths:      server.keyPaths,
		IdentityID: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policy.PolicyIntegritySidecarPath(policy.PolicyPath(root, "alice"))); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ir.ReloadWithPassphrase(passphrase)
	if err == nil {
		t.Fatal("ReloadWithPassphrase() error = nil, want policy integrity failure")
	}
	if !strings.Contains(err.Error(), "policy verification failed") {
		t.Fatalf("ReloadWithPassphrase() error = %v, want policy verification failure", err)
	}
	if pol := ir.Policy(); pol != nil {
		t.Fatalf("Policy() after failed unlock = %+v, want nil", pol)
	}
}

func TestReloadRejectsTamperedPolicyAndKeepsLastKnownGood(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		registry: identity.NewRegistry(),
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := config.DefaultServerConfig()
	passphrase := []byte("policy-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir:    root,
		Paths:      server.keyPaths,
		IdentityID: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	maxFee := uint64(1234)
	stored := &policy.StoredConfig{MaxFeeMicroAlgos: &maxFee}
	masterKey := testMasterKeyForIdentity(t, server.keyPaths, "alice", passphrase)
	defer crypto.ZeroBytes(masterKey)
	if err := policy.SaveStoredConfigWithMasterKey(root, "alice", stored, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildIdentityRuntime(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		ProductIdentityID:     auth.CurrentProductIdentityID(),
	}, signerstartup.IdentityBuildHooks{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.ReloadWithPassphrase(passphrase); err != nil {
		t.Fatalf("ReloadWithPassphrase() error = %v", err)
	}
	if got := ir.Policy().MaxFeeMicroAlgos; got != maxFee {
		t.Fatalf("MaxFeeMicroAlgos after verified load = %d, want %d", got, maxFee)
	}
	if err := os.WriteFile(policy.PolicyPath(root, "alice"), []byte("max_fee_microalgos: 999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ir.Reload(); err == nil {
		t.Fatal("Reload() error = nil, want policy integrity failure")
	} else if !strings.Contains(err.Error(), "policy verification failed") {
		t.Fatalf("Reload() error = %v, want policy verification failure", err)
	}
	if got := ir.Policy().MaxFeeMicroAlgos; got != maxFee {
		t.Fatalf("MaxFeeMicroAlgos after rejected reload = %d, want last-known-good %d", got, maxFee)
	}
}

func testMasterKeyForIdentity(t *testing.T, paths utilkeys.Paths, identityID string, passphrase []byte) []byte {
	t.Helper()
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey() error = %v", err)
	}
	return masterKey
}

func boolPtr(v bool) *bool { return &v }
