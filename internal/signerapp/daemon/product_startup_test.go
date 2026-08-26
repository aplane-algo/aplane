// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storeinit"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	util "github.com/aplane-algo/aplane/internal/tokenfile"
)

func writeTestNodeRole(t *testing.T, root string, role noderole.Role) {
	t.Helper()
	if _, _, err := noderole.SaveInitial(utilkeys.NewPaths(root), role, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProductRuntimeRejectsExtraIdentityBeforeLoadingSecrets(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "identities", "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.DefaultServerConfig()
	_, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              utilkeys.NewPaths(root),
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
	if err == nil {
		t.Fatal("BuildProductRuntime() error = nil")
	}
	if !strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "node role") || strings.Contains(err.Error(), "token") {
		t.Fatalf("BuildProductRuntime() error = %q, want layout rejection before secret loading", err)
	}
}

func TestValidateProductStoreLayoutBlankStore(t *testing.T) {
	root := t.TempDir()
	if err := productruntime.ValidateProductStoreLayout(root); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProductRuntimeAppliesStoredConfig(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := serverconfig.DefaultServerConfig()
	writeTestNodeRole(t, root, noderole.RoleSigner)

	if err := productruntime.SaveStoredSetting(root, "user_auto_approve", true); err != nil {
		t.Fatal(err)
	}
	if err := productruntime.SaveStoredSetting(root, "lock_on_disconnect", false); err != nil {
		t.Fatal(err)
	}
	if err := productruntime.SaveStoredSetting(root, "passphrase_timeout", "30m"); err != nil {
		t.Fatal(err)
	}
	if err := productruntime.SaveStoredSetting(root, "approval_wait", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
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

func TestBuildProductRuntimeRejectsStaleDecommissionedConfig(t *testing.T) {
	root := t.TempDir()
	cfg := serverconfig.DefaultServerConfig()
	writeTestNodeRole(t, root, noderole.RoleSigner)
	configPath := productruntime.ConfigPath(root)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("decommissioned: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              utilkeys.NewPaths(root),
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
	if err == nil || !strings.Contains(err.Error(), "decommissioned") {
		t.Fatalf("BuildProductRuntime() error = %v, want stale decommissioned-field rejection", err)
	}
}

func TestBuildProductRuntimeRejectsStoredMode(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := serverconfig.DefaultServerConfig()
	writeTestNodeRole(t, root, noderole.RoleSigner)

	if err := productruntime.SaveStoredSetting(root, "mode", "sentry"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root); err != nil {
		t.Fatal(err)
	}

	_, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
	if err == nil {
		t.Fatal("BuildProductRuntime() error = nil")
	}
	if !strings.Contains(err.Error(), "runtime config mode is unsupported") {
		t.Fatalf("BuildProductRuntime() error = %q, want unsupported mode", err.Error())
	}
}

func TestBuildProductRuntimeForcesHeadlessOverrides_ProductStorePassfile(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
		dataDir:  root,
	}
	cfg := serverconfig.DefaultServerConfig()
	writeTestNodeRole(t, root, noderole.RoleSigner)
	// Process-global config has NO passphrase_command_argv, so
	// cfg.ShouldLockOnDisconnect() returns true (the default).

	// Write product-store unlock.yaml (simulates selecting Passfile in appass)
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"},
	}
	if err := unlockconfig.SaveUnlockConfig(root, unlockCfg); err != nil {
		t.Fatal(err)
	}

	// Also save an explicit lock_on_disconnect=true in the product runtime config.
	// to prove the headless override wins over both the default AND stored overrides.
	if err := productruntime.SaveStoredSetting(root, "lock_on_disconnect", true); err != nil {
		t.Fatal(err)
	}
	if err := productruntime.SaveStoredSetting(root, "passphrase_timeout", "30m"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
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

func TestBuildProductRuntimeForcesHeadlessOverrides_GlobalPassfile(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
		dataDir:  root,
	}
	cfg := serverconfig.DefaultServerConfig()
	writeTestNodeRole(t, root, noderole.RoleSigner)
	// Process-global passphrase command — ShouldLockOnDisconnect() returns false.
	// But also write a stored override to prove the headless path catches it.
	cfg.PassphraseCommandArgv = []string{"/usr/local/bin/appass-file", "/tmp/secret"}

	if err := productruntime.SaveStoredSetting(root, "lock_on_disconnect", true); err != nil {
		t.Fatal(err)
	}
	if err := productruntime.SaveStoredSetting(root, "passphrase_timeout", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, err := util.LoadAPlaneToken(root); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
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

func TestBuildProductRuntimeRoutesLockedNotificationByIdentity(t *testing.T) {
	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
		dataDir:  root,
	}
	cfg := serverconfig.DefaultServerConfig()
	hub := &recordingAdminHub{}
	writeTestNodeRole(t, root, noderole.RoleSigner)

	if _, err := util.LoadAPlaneToken(root); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{
		NotifyLocked: func() {
			hub.NotifyLocked(adminproto.SignerLockedNotification{Reason: "locked"})
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ir.SetUnlocked()
	ir.Lock()

	if !hub.lockedCalled {
		t.Fatal("NotifyLocked was not called")
	}
}

func TestBuildProductRuntimeLoadsStoredPolicy(t *testing.T) {
	RegisterProviders()

	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := serverconfig.DefaultServerConfig()
	passphrase := []byte("policy-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir: root,
		Paths:   server.keyPaths,
	}); err != nil {
		t.Fatal(err)
	}
	maxFee := uint64(1234)
	stored := &policy.StoredConfig{StoredPolicyCore: policy.StoredPolicyCore{RejectForeignRekey: boolPtr(false), MaxFeeMicroAlgos: &maxFee, MaxASAAmounts: map[string]map[string]uint64{
		"testnet": {
			"31566704": 77,
		},
	}},
	}
	masterKey := testKeyringForStore(t, server.keyPaths, passphrase)
	active, err := genstore.ResolveActive(server.keyPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SaveStoredConfigActiveWithKeyring(active, stored, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
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

func TestBuildProductRuntimeRejectsUnsignedPolicyOnUnlock(t *testing.T) {
	RegisterProviders()

	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := serverconfig.DefaultServerConfig()
	passphrase := []byte("policy-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir: root,
		Paths:   server.keyPaths,
	}); err != nil {
		t.Fatal(err)
	}
	active, err := genstore.ResolveActive(server.keyPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(active.PolicyIntegritySidecar()); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
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

func TestBuildProductRuntimeRejectsTamperedNodeRoleOnUnlock(t *testing.T) {
	RegisterProviders()

	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := serverconfig.DefaultServerConfig()
	passphrase := []byte("role-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir: root,
		Paths:   server.keyPaths,
	}); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(server.keyPaths.NodeRolePath(), []byte("schema_version: 1\nrole: sentry\n"), 0o660); err != nil {
		t.Fatal(err)
	}
	_, err = ir.ReloadWithPassphrase(passphrase)
	if err == nil {
		t.Fatal("ReloadWithPassphrase() error = nil, want node role integrity failure")
	}
	if !strings.Contains(err.Error(), "node role verification failed") {
		t.Fatalf("ReloadWithPassphrase() error = %v, want node role verification failure", err)
	}
}

func TestReloadRejectsTamperedPolicyAndKeepsLastKnownGood(t *testing.T) {
	RegisterProviders()

	root := t.TempDir()
	server := &Signer{
		keyPaths: utilkeys.NewPaths(root),
	}
	cfg := serverconfig.DefaultServerConfig()
	passphrase := []byte("policy-passphrase")
	defer crypto.ZeroBytes(passphrase)
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir: root,
		Paths:   server.keyPaths,
	}); err != nil {
		t.Fatal(err)
	}
	maxFee := uint64(1234)
	stored := &policy.StoredConfig{StoredPolicyCore: policy.StoredPolicyCore{MaxFeeMicroAlgos: &maxFee}}
	masterKey := testKeyringForStore(t, server.keyPaths, passphrase)
	active, err := genstore.ResolveActive(server.keyPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SaveStoredConfigActiveWithKeyring(active, stored, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              server.keyPaths,
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
	}, signerstartup.ProductBuildHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.ReloadWithPassphrase(passphrase); err != nil {
		t.Fatalf("ReloadWithPassphrase() error = %v", err)
	}
	if got := ir.Policy().MaxFeeMicroAlgos; got != maxFee {
		t.Fatalf("MaxFeeMicroAlgos after verified load = %d, want %d", got, maxFee)
	}
	if err := os.WriteFile(active.PolicyPath(), []byte("max_fee_microalgos: 999999\n"), 0o600); err != nil {
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

func testKeyringForStore(t *testing.T, paths utilkeys.Paths, passphrase []byte) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}

func boolPtr(v bool) *bool { return &v }
