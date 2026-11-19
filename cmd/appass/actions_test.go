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
	setServiceFile(filepath.Join(os.TempDir(), "aplane-appass-test-missing.service"))
	os.Exit(m.Run())
}

func TestEnforceAppassExecutionModeRejectsRootForLocalDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	currentEUID = func() int { return 0 }

	err := enforceAppassExecutionMode(dataDir, false)
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

	err := enforceAppassExecutionMode(dataDir, true)
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

func TestParseAppassOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    appassOptions
		wantErr bool
	}{
		{name: "data dir", args: []string{"-d", "/tmp/signer"}, want: appassOptions{dataDir: "/tmp/signer"}},
		{name: "version", args: []string{"--version"}, want: appassOptions{version: true}},
		{name: "check", args: []string{"--check"}, want: appassOptions{check: true}},
		{name: "unknown flag", args: []string{"--unknown"}, wantErr: true},
		{name: "unknown flag with value", args: []string{"--unknown=value"}, wantErr: true},
		{name: "positional argument", args: []string{"unexpected"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAppassOptions(test.args)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseAppassOptions(%q) error = %v, wantErr %v", test.args, err, test.wantErr)
			}
			if !test.wantErr && got != test.want {
				t.Fatalf("parseAppassOptions(%q) = %+v, want %+v", test.args, got, test.want)
			}
		})
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

func TestCurrentAutoUnlockMethodReportsUnreadableConfig(t *testing.T) {
	dataDir := t.TempDir()
	if method, err := currentAutoUnlockMethod(dataDir); err != nil || method != "none" {
		t.Fatalf("missing unlock config = (%q, %v), want (none, nil)", method, err)
	}

	path := unlockconfig.UnlockConfigPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("passphrase_command_argv: [unterminated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if method, err := currentAutoUnlockMethod(dataDir); err == nil || method != "unreadable" {
		t.Fatalf("malformed unlock config = (%q, %v), want (unreadable, an error)", method, err)
	}
}

// A malformed unlock.yaml must not lock appass out of repairing it: Clear
// removes it and whatever either method left behind.
func TestExecuteClearRemovesUnreadableConfig(t *testing.T) {
	stubSignerStopped(t)

	dataDir := t.TempDir()
	path := unlockconfig.UnlockConfigPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("passphrase_command_argv: [unterminated"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A passfile setup left its plaintext passphrase behind; clearing must
	// remove it even though unlock.yaml no longer says which method it was.
	passFile := filepath.Join(filepath.Dir(path), "passphrase")
	if err := os.WriteFile(passFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executeClear(dataDir, true); err != nil {
		t.Fatalf("executeClear() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unlock.yaml after clear: stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(passFile); !os.IsNotExist(err) {
		t.Fatalf("passphrase file after clear: stat error = %v, want not exist", err)
	}
}

// setupDataDir creates a minimal data directory with a product-store unlock.yaml pointing to passfile.
func setupDataDir(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()

	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", filepath.Join(dataDir, "identities", "default", "passphrase")},
	}
	if err := unlockconfig.SaveUnlockConfig(dataDir, unlockCfg); err != nil {
		t.Fatalf("save unlock config: %v", err)
	}

	// Write a dummy passphrase file
	passDir := filepath.Join(dataDir, "identities", "default")
	if err := os.WriteFile(filepath.Join(passDir, "passphrase"), []byte("secret"), 0600); err != nil {
		t.Fatalf("write passphrase: %v", err)
	}

	return dataDir
}

func TestExecuteClear_ClearsProductStoreConfig(t *testing.T) {
	stubSignerStopped(t)

	dataDir := setupDataDir(t)

	// Verify starting state: method is passfile
	method, err := currentAutoUnlockMethod(dataDir)
	if err != nil {
		t.Fatalf("currentAutoUnlockMethod before clear: %v", err)
	}
	if method != "passfile" {
		t.Fatalf("method before clear = %q, want %q", method, "passfile")
	}

	// Clear
	warning, err := executeClear(dataDir, true)
	if err != nil {
		t.Fatalf("executeClear: %v", err)
	}
	if warning != "" {
		t.Logf("warning: %s", warning)
	}

	// After clear, method must be "none".
	method, err = currentAutoUnlockMethod(dataDir)
	if err != nil {
		t.Fatalf("currentAutoUnlockMethod after clear: %v", err)
	}
	if method != "none" {
		t.Fatalf("method after clear = %q, want %q", method, "none")
	}
}

func TestExecuteClear_RemovesProductStoreSystemdCredsFile(t *testing.T) {
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
	if err := unlockconfig.SaveUnlockConfig(dataDir, unlockCfg); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}

	credPath := filepath.Join(identityDir, "passphrase.cred")
	if err := os.WriteFile(credPath, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(passphrase.cred) error = %v", err)
	}

	if _, err := executeClear(dataDir, true); err != nil {
		t.Fatalf("executeClear() error = %v", err)
	}

	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatalf("Stat(passphrase.cred) error = %v, want not exists", err)
	}
}

// An unlock.yaml that cannot be read (as opposed to one that does not parse)
// stops every action, so the menu offers none.
func TestMenuOffersNoActionForUnreadableUnlockConfig(t *testing.T) {
	m := Model{method: methodReadError, isLocal: true}
	for _, item := range m.buildMenu() {
		if item.action != "quit" && !item.disabled {
			t.Fatalf("menu item %q enabled with an unreadable unlock.yaml", item.label)
		}
	}
}

// otherStoreUnit installs an apsigner unit for some other, systemd-managed
// store as the host's unit, and returns its path and contents.
func otherStoreUnit(t *testing.T) (string, string) {
	t.Helper()
	unit := "[Service]\n" +
		"LoadCredentialEncrypted=aplane-passphrase:/var/lib/apsigner/identities/default/passphrase.cred\n" +
		"ExecStart=/usr/local/bin/apsigner\n" +
		"User=aplane\n" +
		"Group=aplane\n"
	path := filepath.Join(t.TempDir(), "apsigner.service")
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	original := currentServiceFile()
	setServiceFile(path)
	t.Cleanup(func() { setServiceFile(original) })
	return path, unit
}

// localSystemdCredsDataDir is a local data directory whose unlock.yaml names
// the systemd-creds helper, with its credential file.
func localSystemdCredsDataDir(t *testing.T) (dataDir, credPath string) {
	t.Helper()
	dataDir = t.TempDir()
	identityDir := filepath.Join(dataDir, "identities", "default")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credPath = filepath.Join(identityDir, "passphrase.cred")
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-systemd-creds", credPath},
	}
	if err := unlockconfig.SaveUnlockConfig(dataDir, unlockCfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credPath, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dataDir, credPath
}

func assertUnitUnchanged(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("another store's unit was edited:\n%s", got)
	}
}

// The mode is the data directory's own. An apsigner unit on the host belongs
// to a systemd-managed store, so clearing a local directory's auto-unlock
// needs no root and leaves that unit alone.
func TestExecuteClearLocalDataDirIgnoresHostUnit(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a local data directory is managed without root")
	}
	stubSignerStopped(t)
	unitPath, unit := otherStoreUnit(t)
	dataDir, credPath := localSystemdCredsDataDir(t)

	warning, err := executeClear(dataDir, true)
	if err != nil {
		t.Fatalf("executeClear() error = %v", err)
	}
	if warning != "" {
		t.Fatalf("executeClear() warning = %q", warning)
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatalf("passphrase.cred after clear: stat error = %v, want not exist", err)
	}
	if method, err := currentAutoUnlockMethod(dataDir); err != nil || method != unlockconfig.MethodNone {
		t.Fatalf("method after clear = (%q, %v), want none", method, err)
	}
	assertUnitUnchanged(t, unitPath, unit)
}

// Switching a local data directory from systemd-creds to a passfile removes
// its own credential and never edits the host's unit for another store.
func TestExecuteSetPassfileLocalDataDirIgnoresHostUnit(t *testing.T) {
	stubSignerStopped(t)
	// No systemctl may run: a daemon-reload attempt fails here instead.
	t.Setenv("PATH", t.TempDir())
	unitPath, unit := otherStoreUnit(t)
	dataDir, credPath := localSystemdCredsDataDir(t)

	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "appass-file"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	svc := &serviceInfo{BinDir: binDir, StoreUID: os.Geteuid(), StoreGID: os.Getegid()}

	warning, err := executeSetPassfile(dataDir, []byte("local-secret"), svc, true)
	if err != nil {
		t.Fatalf("executeSetPassfile() error = %v", err)
	}
	if warning != "" {
		t.Fatalf("executeSetPassfile() warning = %q", warning)
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatalf("passphrase.cred after switch: stat error = %v, want not exist", err)
	}
	if method, err := currentAutoUnlockMethod(dataDir); err != nil || method != unlockconfig.MethodPassfile {
		t.Fatalf("method after switch = (%q, %v), want passfile", method, err)
	}
	assertUnitUnchanged(t, unitPath, unit)
}
