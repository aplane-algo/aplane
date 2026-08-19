// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"errors"
	"os"
	"testing"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestSaveInitialAndVerifyWithKeyring(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("01234567890123456789012345678901")

	roleBytes, doc, err := SaveInitial(paths, RoleSigner, time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if doc.Role != RoleSigner {
		t.Fatalf("Role = %q, want %q", doc.Role, RoleSigner)
	}
	if err := SaveIdentitySidecarWithKeyring(paths, roleBytes, cryptotest.Keyring(t, masterKey), time.Unix(100, 0)); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	sidecar, err := LoadSidecar(paths.NodeRoleIntegritySidecar())
	if err != nil {
		t.Fatalf("LoadSidecar() error = %v", err)
	}
	if sidecar.Version != IntegritySidecarVersion || sidecar.IntegrityTerm != 1 {
		t.Fatalf("sidecar version/term = %d/%d, want %d/1", sidecar.Version, sidecar.IntegrityTerm, IntegritySidecarVersion)
	}
	verified, err := LoadAndVerifyWithKeyring(paths, cryptotest.Keyring(t, masterKey))
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

	roleBytes, _, err := SaveInitial(paths, RoleSigner, time.Now())
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if err := SaveIdentitySidecarWithKeyring(paths, roleBytes, cryptotest.Keyring(t, masterKey), time.Now()); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	if err := os.WriteFile(paths.NodeRolePath(), []byte("schema_version: 1\nrole: sentry\n"), 0o660); err != nil {
		t.Fatalf("WriteFile(tamper) error = %v", err)
	}
	_, err = LoadAndVerifyWithKeyring(paths, cryptotest.Keyring(t, masterKey))
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("LoadAndVerifyWithKeyring(tampered) error = %v, want ErrRoleMismatch", err)
	}
}

func TestVerifyRejectsWrongMasterKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("01234567890123456789012345678901")
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	defer apcrypto.ZeroBytes(wrongKey)

	roleBytes, _, err := SaveInitial(paths, RoleSigner, time.Now())
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if err := SaveIdentitySidecarWithKeyring(paths, roleBytes, cryptotest.Keyring(t, masterKey), time.Now()); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	_, err = LoadAndVerifyWithKeyring(paths, cryptotest.Keyring(t, wrongKey))
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("LoadAndVerifyWithKeyring(wrong key) error = %v, want ErrRoleMismatch", err)
	}
}

func TestVerifyRejectsUnauthorizedIntegrityTerm(t *testing.T) {
	kr := cryptotest.Keyring(t, []byte("01234567890123456789012345678901"))
	roleBytes := []byte("schema_version: 1\nrole: signer\n")
	sidecar, err := Sign(roleBytes, kr, time.Now(), 0)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	sidecar.IntegrityTerm++
	if err := Verify(roleBytes, sidecar, kr); !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("Verify() error = %v, want ErrRoleMismatch", err)
	}
}

func TestIntegritySidecarParsingIsStrict(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"version":2,"unknown":true}`),
		[]byte(`{"version":2}{}`),
	} {
		if _, err := ParseSidecar(data); !errors.Is(err, ErrRoleSidecarBad) {
			t.Fatalf("ParseSidecar(%q) error = %v, want ErrRoleSidecarBad", data, err)
		}
	}
}
