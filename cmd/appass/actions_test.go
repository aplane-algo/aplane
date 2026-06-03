// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
)

func TestMain(m *testing.M) {
	serviceFilePath = filepath.Join(os.TempDir(), "aplane-appass-test-missing.service")
	os.Exit(m.Run())
}

func TestEnforceAppassExecutionModeRejectsRootForLocalDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	currentEUID = func() int { return 0 }

	err := enforceAppassExecutionMode(dataDir, "default", false)
	if err == nil {
		t.Fatal("enforceAppassExecutionMode() error = nil, want local root refusal")
	}
	for _, want := range []string{
		"local signer data directory",
		"must not be managed as root",
		"appass -d " + dataDir,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestEnforceAppassExecutionModeRejectsNonRootForProductionDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	currentEUID = func() int { return 1000 }

	err := enforceAppassExecutionMode(dataDir, "default", true)
	if err == nil {
		t.Fatal("enforceAppassExecutionMode() error = nil, want production non-root refusal")
	}
	for _, want := range []string{
		"systemd-managed data directory",
		"requires root",
		"sudo appass -d " + dataDir,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

// stubSignerStopped makes requireSignerStopped succeed (socket not found).
func stubSignerStopped(t *testing.T) {
	t.Helper()
	dialSignerIPCMu.Lock()
	orig := dialSignerIPC
	dialSignerIPC = func(string) (net.Conn, error) {
		return nil, syscall.ENOENT
	}
	dialSignerIPCMu.Unlock()
	t.Cleanup(func() {
		dialSignerIPCMu.Lock()
		dialSignerIPC = orig
		dialSignerIPCMu.Unlock()
	})
}

// setupDataDir creates a minimal data directory with an identity-scoped unlock.yaml pointing to passfile.
func setupDataDir(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()

	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", filepath.Join(dataDir, "identities", "default", "passphrase")},
	}
	if err := unlockconfig.SaveUnlockConfig(dataDir, "default", unlockCfg); err != nil {
		t.Fatalf("save unlock config: %v", err)
	}

	// Write a dummy passphrase file
	passDir := filepath.Join(dataDir, "identities", "default")
	if err := os.WriteFile(filepath.Join(passDir, "passphrase"), []byte("secret"), 0600); err != nil {
		t.Fatalf("write passphrase: %v", err)
	}

	return dataDir
}

func TestExecuteClear_ClearsIdentityScopedConfig(t *testing.T) {
	stubSignerStopped(t)

	dataDir := setupDataDir(t)

	// Verify starting state: method is passfile
	method, err := currentAutoUnlockMethod(dataDir, "default")
	if err != nil {
		t.Fatalf("currentAutoUnlockMethod before clear: %v", err)
	}
	if method != "passfile" {
		t.Fatalf("method before clear = %q, want %q", method, "passfile")
	}

	// Clear
	warning, err := executeClear(dataDir, "default")
	if err != nil {
		t.Fatalf("executeClear: %v", err)
	}
	if warning != "" {
		t.Logf("warning: %s", warning)
	}

	// After clear, method must be "none".
	method, err = currentAutoUnlockMethod(dataDir, "default")
	if err != nil {
		t.Fatalf("currentAutoUnlockMethod after clear: %v", err)
	}
	if method != "none" {
		t.Fatalf("method after clear = %q, want %q", method, "none")
	}
}

func TestExecuteClear_RemovesIdentityScopedSystemdCredsFile(t *testing.T) {
	stubSignerStopped(t)

	dataDir := t.TempDir()
	identityID := "default"
	identityDir := filepath.Join(dataDir, "identities", identityID)
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(identityDir) error = %v", err)
	}

	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-systemd-creds", filepath.Join(identityDir, "passphrase.cred")},
	}
	if err := unlockconfig.SaveUnlockConfig(dataDir, identityID, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}

	credPath := filepath.Join(identityDir, "passphrase.cred")
	if err := os.WriteFile(credPath, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(passphrase.cred) error = %v", err)
	}

	if _, err := executeClear(dataDir, identityID); err != nil {
		t.Fatalf("executeClear() error = %v", err)
	}

	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatalf("Stat(passphrase.cred) error = %v, want not exists", err)
	}
}
