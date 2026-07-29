// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"errors"
	"os"
	"testing"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestSaveInitialAndVerifyWithMasterKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("01234567890123456789012345678901")
	defer apcrypto.ZeroBytes(masterKey)

	roleBytes, doc, err := SaveInitial(paths, RoleSigner, time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if doc.Role != RoleSigner {
		t.Fatalf("Role = %q, want %q", doc.Role, RoleSigner)
	}
	if err := SaveIdentitySidecarWithKeyring(paths, "default", roleBytes, keyringForTest(t, masterKey), time.Unix(100, 0)); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	verified, err := LoadAndVerifyWithKeyring(paths, "default", keyringForTest(t, masterKey))
	if err != nil {
		t.Fatalf("LoadAndVerifyWithKeyring() error = %v", err)
	}
	if verified.Role != RoleSigner {
		t.Fatalf("verified Role = %q, want %q", verified.Role, RoleSigner)
	}
}

func TestSaveInitialRefusesOverwrite(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if _, _, err := SaveInitial(paths, RoleSigner, time.Now()); err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	_, _, err := SaveInitial(paths, RoleSentry, time.Now())
	if !errors.Is(err, ErrRoleFileExists) {
		t.Fatalf("SaveInitial(overwrite) error = %v, want ErrRoleFileExists", err)
	}
}

func TestVerifyRejectsTamperedNodeRole(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("01234567890123456789012345678901")
	defer apcrypto.ZeroBytes(masterKey)

	roleBytes, _, err := SaveInitial(paths, RoleSigner, time.Now())
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if err := SaveIdentitySidecarWithKeyring(paths, "default", roleBytes, keyringForTest(t, masterKey), time.Now()); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	if err := os.WriteFile(paths.NodeRolePath(), []byte("schema_version: 1\nrole: sentry\n"), 0o660); err != nil {
		t.Fatalf("WriteFile(tamper) error = %v", err)
	}
	_, err = LoadAndVerifyWithKeyring(paths, "default", keyringForTest(t, masterKey))
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("LoadAndVerifyWithKeyring(tampered) error = %v, want ErrRoleMismatch", err)
	}
}

func TestVerifyRejectsWrongMasterKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("01234567890123456789012345678901")
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	defer apcrypto.ZeroBytes(masterKey)
	defer apcrypto.ZeroBytes(wrongKey)

	roleBytes, _, err := SaveInitial(paths, RoleSigner, time.Now())
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if err := SaveIdentitySidecarWithKeyring(paths, "default", roleBytes, keyringForTest(t, masterKey), time.Now()); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	_, err = LoadAndVerifyWithKeyring(paths, "default", keyringForTest(t, wrongKey))
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("LoadAndVerifyWithKeyring(wrong key) error = %v, want ErrRoleMismatch", err)
	}
}

// keyringForTest wraps a raw term-1 key as a keyring, matching what the store
// holds while phase 2 migrates callers from raw keys to the keyring.
func keyringForTest(t *testing.T, masterKey []byte) *apcrypto.Keyring {
	t.Helper()
	kr, err := apcrypto.NewKeyringFromKey(masterKey)
	if err != nil {
		t.Fatalf("NewKeyringFromKey(): %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}
