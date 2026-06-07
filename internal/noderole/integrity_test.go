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
	if err := SaveIdentitySidecarWithMasterKey(paths, "default", roleBytes, masterKey, time.Unix(100, 0)); err != nil {
		t.Fatalf("SaveIdentitySidecarWithMasterKey() error = %v", err)
	}
	verified, err := LoadAndVerifyWithMasterKey(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("LoadAndVerifyWithMasterKey() error = %v", err)
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
	_, _, err := SaveInitial(paths, RoleAttestor, time.Now())
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
	if err := SaveIdentitySidecarWithMasterKey(paths, "default", roleBytes, masterKey, time.Now()); err != nil {
		t.Fatalf("SaveIdentitySidecarWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(paths.NodeRolePath(), []byte("schema_version: 1\nrole: attestor\n"), 0o660); err != nil {
		t.Fatalf("WriteFile(tamper) error = %v", err)
	}
	_, err = LoadAndVerifyWithMasterKey(paths, "default", masterKey)
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("LoadAndVerifyWithMasterKey(tampered) error = %v, want ErrRoleMismatch", err)
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
	if err := SaveIdentitySidecarWithMasterKey(paths, "default", roleBytes, masterKey, time.Now()); err != nil {
		t.Fatalf("SaveIdentitySidecarWithMasterKey() error = %v", err)
	}
	_, err = LoadAndVerifyWithMasterKey(paths, "default", wrongKey)
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("LoadAndVerifyWithMasterKey(wrong key) error = %v, want ErrRoleMismatch", err)
	}
}
