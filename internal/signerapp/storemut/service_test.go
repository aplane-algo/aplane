// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storemut

import (
	"context"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	util "github.com/aplane-algo/aplane/internal/tokenfile"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

type recordingUpdater struct {
	token string
	calls int
}

var testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"
var registerProvidersOnce sync.Once

func (r *recordingUpdater) UpdateToken(token string) {
	r.token = token
	r.calls++
}

func registerProviders() {
	registerProvidersOnce.Do(func() {
		lsigsignerreg.RegisterSigner()
		ed25519signerreg.RegisterSigner()
	})
}

func setupKeystore(t *testing.T, identityID string) (utilkeys.Paths, *crypto.Keyring, func()) {
	t.Helper()
	registerProviders()

	tmpDir := t.TempDir()
	paths := utilkeys.NewPaths(tmpDir)
	genstoretest.MintFirst(t, paths, identityID)

	userDir := paths.ProductDir()
	if _, err := crypto.CreateKeyringStore(userDir, []byte("test-passphrase-for-storemut")); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	kr, err := crypto.OpenKeyringStore(userDir, []byte("test-passphrase-for-storemut"))
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	cleanup := kr.Zero
	return paths, kr, cleanup
}

func TestRevokeTokenWritesAndUpdatesDependents(t *testing.T) {
	tmpDir := t.TempDir()
	paths := utilkeys.NewPaths(tmpDir)
	genstoretest.MintFirst(t, paths, "default")

	httpUpdater := &recordingUpdater{}
	sshUpdater := &recordingUpdater{}
	svc := New("default", paths, httpUpdater, sshUpdater)

	tokenPath, err := svc.RevokeToken()
	if err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	tokenOnDisk, err := util.ReadToken(tokenPath)
	if err != nil {
		t.Fatalf("ReadToken() error = %v", err)
	}
	if tokenOnDisk == "" {
		t.Fatal("expected non-empty token on disk")
	}
	if httpUpdater.calls != 1 || httpUpdater.token != tokenOnDisk {
		t.Fatalf("http updater = (%d calls, %q), want (1 call, %q)", httpUpdater.calls, httpUpdater.token, tokenOnDisk)
	}
	if sshUpdater.calls != 1 || sshUpdater.token != tokenOnDisk {
		t.Fatalf("ssh updater = (%d calls, %q), want (1 call, %q)", sshUpdater.calls, sshUpdater.token, tokenOnDisk)
	}
}

func TestDeleteKeyMovesFileToDeletedKeys(t *testing.T) {
	tmpDir := t.TempDir()
	paths := utilkeys.NewPaths(tmpDir)
	genstoretest.MintFirst(t, paths, "default")

	keyPath := keys.AccountKeyFilePath(paths, "default", "ADDR")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key-data"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	svc := New("default", paths, nil, nil)
	result, err := svc.DeleteKey("ADDR", keyPath)
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected source file removed, stat err = %v", err)
	}
	if _, err := os.Stat(result.DeletedPath); err != nil {
		t.Fatalf("expected deleted key at %s: %v", result.DeletedPath, err)
	}
	if wantDir := paths.DeletedKeysDir(); filepath.Dir(result.DeletedPath) != wantDir {
		t.Fatalf("deleted path dir = %s, want %s", filepath.Dir(result.DeletedPath), wantDir)
	}
}

func TestGenerateKeyCreatesPersistedKey(t *testing.T) {
	const identityID = "storemut-generate"
	paths, masterKey, cleanup := setupKeystore(t, identityID)
	defer cleanup()

	svc := New(identityID, paths, nil, nil)
	result, err := svc.GenerateKeyWithActivatedContext(context.Background(), "ed25519", masterKey, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if result.Address == "" {
		t.Fatal("expected generated address")
	}
	if result.KeyFile == "" {
		t.Fatal("expected generated key file path")
	}
	if _, err := os.Stat(result.KeyFile); err != nil {
		t.Fatalf("expected key file at %s: %v", result.KeyFile, err)
	}
	if got, want := filepath.Dir(result.KeyFile), mustActiveKeysDirStoremut(t, paths, identityID); got != want {
		t.Fatalf("key dir = %s, want %s", got, want)
	}
}

func TestImportKeyFromMnemonicCreatesPersistedKey(t *testing.T) {
	const identityID = "storemut-import"
	paths, masterKey, cleanup := setupKeystore(t, identityID)
	defer cleanup()

	svc := New(identityID, paths, nil, nil)
	result, err := svc.ImportKeyFromMnemonicWithActivated("ed25519", testMnemonic, masterKey, nil, nil)
	if err != nil {
		t.Fatalf("ImportKeyFromMnemonic() error = %v", err)
	}
	if result.Address == "" {
		t.Fatal("expected imported address")
	}
	if result.KeyFile == "" {
		t.Fatal("expected imported key file path")
	}
	if _, err := os.Stat(result.KeyFile); err != nil {
		t.Fatalf("expected key file at %s: %v", result.KeyFile, err)
	}
	if got, want := filepath.Dir(result.KeyFile), mustActiveKeysDirStoremut(t, paths, identityID); got != want {
		t.Fatalf("key dir = %s, want %s", got, want)
	}
}

func TestSaveGenericLSigCreatesPersistedKeyFile(t *testing.T) {
	paths, masterKey, cleanup := setupKeystore(t, auth.DefaultIdentityID)
	defer cleanup()

	svc := New("default", paths, nil, nil)
	salted, err := lsigsalt.FindOffCurveAtOffset([]byte{0x06, 0x81, 0x01, 0x00}, 3)
	if err != nil {
		t.Fatalf("FindOffCurveAtOffset() error = %v", err)
	}
	err = svc.SaveGenericLSig(
		"test.timed-policy.v1",
		map[string]string{"unlock_round": "123"},
		salted.Bytecode,
		salted.Counter,
		false,
		"#pragma version 10\nint 1\nreturn",
		nil,
		lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling),
		masterKey,
	)
	if err != nil {
		t.Fatalf("SaveGenericLSig() error = %v", err)
	}

	keyPath := keys.AccountKeyFilePath(paths, "default", salted.Address.String())
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected generic lsig file at %s: %v", keyPath, err)
	}
	encrypted, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	credentialContext, err := keys.CredentialContextForFile(keyPath)
	if err != nil {
		t.Fatalf("CredentialContextForFile() error = %v", err)
	}
	decrypted, err := masterKey.Open(encrypted, credentialContext)
	if err != nil {
		t.Fatalf("decryptWithTermKey() error = %v", err)
	}
	defer crypto.ZeroBytes(decrypted)
	payload, err := keys.ParsePayload(decrypted)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	if payload.Category != keys.CategoryGenericLsig || payload.KeyType != "test.timed-policy.v1" {
		t.Fatalf("payload = (%q, %q), want canonical generic LogicSig", payload.Category, payload.KeyType)
	}
}

func TestSaveServerSettingPersistsConfigValue(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\nuser_auto_approve: false\n"), 0o640); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	svc := New("default", utilkeys.NewPaths(dir), nil, nil)
	if err := svc.SaveServerSetting(dir, "theme", "dark"); err != nil {
		t.Fatalf("SaveServerSetting() error = %v", err)
	}

	cfg, err := serverconfig.LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if cfg.Theme != "dark" {
		t.Fatalf("theme = %q, want %q", cfg.Theme, "dark")
	}
	if cfg.UserAutoApprove {
		t.Fatal("user_auto_approve = true, want false")
	}
}

func TestSaveIdentitySettingPersistsIdentityConfigValue(t *testing.T) {
	dir := t.TempDir()

	svc := New("default", utilkeys.NewPaths(dir), nil, nil)
	if err := svc.SaveIdentitySetting(dir, "user_auto_approve", true); err != nil {
		t.Fatalf("SaveIdentitySetting() error = %v", err)
	}
	if err := svc.SaveIdentitySetting(dir, "passphrase_timeout", "30m"); err != nil {
		t.Fatalf("SaveIdentitySetting() error = %v", err)
	}

	cfg, err := identity.LoadStoredConfig(dir, "default")
	if err != nil {
		t.Fatalf("LoadStoredConfig() error = %v", err)
	}
	if cfg.UserAutoApprove == nil || !*cfg.UserAutoApprove {
		t.Fatal("user_auto_approve not persisted to identity config")
	}
	if cfg.PassphraseTimeout != "30m" {
		t.Fatalf("passphrase_timeout = %q, want %q", cfg.PassphraseTimeout, "30m")
	}
}

func mustActiveKeysDirStoremut(t *testing.T, paths utilkeys.Paths, identityID string) string {
	t.Helper()
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active.KeysDir()
}
