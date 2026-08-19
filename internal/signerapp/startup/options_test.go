// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestResolveUnlockConfigPrefersIdentityScoped(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := serverconfig.DefaultServerConfig()
	cfg.PassphraseCommandArgv = []string{"global-pass", "/tmp/global"}
	cfg.PassphraseCommandEnv = map[string]string{"GLOBAL": "1"}

	want := &identity.UnlockConfig{
		PassphraseCommandArgv: []string{"identity-pass", "/tmp/identity"},
		PassphraseCommandEnv:  map[string]string{"IDENTITY": "1"},
	}
	if err := identity.SaveUnlockConfig(root, want); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}

	got, err := ResolveUnlockConfig(root, "alice", &cfg)
	if err != nil {
		t.Fatalf("ResolveUnlockConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveUnlockConfig() = %+v, want %+v", got, want)
	}
}

func TestResolveUnlockConfigFallsBackToGlobal(t *testing.T) {
	t.Parallel()

	cfg := serverconfig.DefaultServerConfig()
	cfg.PassphraseCommandArgv = []string{"global-pass", "/tmp/global"}
	cfg.PassphraseCommandEnv = map[string]string{"GLOBAL": "1"}

	got, err := ResolveUnlockConfig(t.TempDir(), "alice", &cfg)
	if err != nil {
		t.Fatalf("ResolveUnlockConfig() error = %v", err)
	}
	want := &identity.UnlockConfig{
		PassphraseCommandArgv: cfg.PassphraseCommandArgv,
		PassphraseCommandEnv:  cfg.PassphraseCommandEnv,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveUnlockConfig() = %+v, want %+v", got, want)
	}
}

func TestBuildUnlockPlanLockedWithoutKeystore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	opts := &Options{
		DataDir:    root,
		Config:     serverconfig.DefaultServerConfig(),
		Paths:      storepaths.NewPaths(root),
		IdentityID: "default",
	}

	plan, err := BuildUnlockPlan(opts, false, "")
	if err != nil {
		t.Fatalf("BuildUnlockPlan() error = %v", err)
	}
	if !plan.StartLocked {
		t.Fatal("BuildUnlockPlan() StartLocked = false, want true")
	}
	if len(plan.Passphrase) != 0 {
		t.Fatalf("BuildUnlockPlan() passphrase len = %d, want 0", len(plan.Passphrase))
	}
	if plan.Source != UnlockSourceIPC {
		t.Fatalf("BuildUnlockPlan() source = %q, want %q", plan.Source, UnlockSourceIPC)
	}
}

func TestBuildUnlockPlanUsesTestPassphrase(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	passphrase := []byte("test-passphrase")
	paths := storepaths.NewPaths(root)
	if _, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), passphrase); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	opts := &Options{
		DataDir:    root,
		Config:     serverconfig.DefaultServerConfig(),
		Paths:      paths,
		IdentityID: "default",
	}

	plan, err := BuildUnlockPlan(opts, true, string(passphrase))
	if err != nil {
		t.Fatalf("BuildUnlockPlan() error = %v", err)
	}
	if plan.StartLocked {
		t.Fatal("BuildUnlockPlan() StartLocked = true, want false")
	}
	if plan.Source != UnlockSourceTestPassphrase {
		t.Fatalf("BuildUnlockPlan() source = %q, want %q", plan.Source, UnlockSourceTestPassphrase)
	}
	if string(plan.Passphrase) != string(passphrase) {
		t.Fatalf("BuildUnlockPlan() passphrase = %q, want %q", string(plan.Passphrase), string(passphrase))
	}
	crypto.ZeroBytes(plan.Passphrase)
}

func TestBuildUnlockPlanUsesPassphraseCommand(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	passphrase := []byte("command-passphrase")
	paths := storepaths.NewPaths(root)
	if _, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), passphrase); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	helper, marker := writePassphraseHelper(t, root, string(passphrase))

	cfg := serverconfig.DefaultServerConfig()
	cfg.PassphraseCommandArgv = []string{helper, marker}
	opts := &Options{
		DataDir:    root,
		Config:     cfg,
		Paths:      paths,
		IdentityID: "default",
	}

	plan, err := BuildUnlockPlan(opts, true, "")
	if err != nil {
		t.Fatalf("BuildUnlockPlan() error = %v", err)
	}
	defer crypto.ZeroBytes(plan.Passphrase)
	if plan.StartLocked {
		t.Fatal("BuildUnlockPlan() StartLocked = true, want false")
	}
	if plan.Source != UnlockSourcePassphraseCommand {
		t.Fatalf("BuildUnlockPlan() source = %q, want %q", plan.Source, UnlockSourcePassphraseCommand)
	}
	if string(plan.Passphrase) != string(passphrase) {
		t.Fatalf("BuildUnlockPlan() passphrase = %q, want configured command output", string(plan.Passphrase))
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("passphrase helper marker: %v", err)
	}
}

func TestValidateAndBuildUnlockPlanRejectsExtraIdentityBeforePassphraseCommand(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	passphrase := []byte("command-passphrase")
	paths := storepaths.NewPaths(root)
	if _, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), passphrase); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "identities", "other-identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	helper, marker := writePassphraseHelper(t, root, string(passphrase))
	cfg := serverconfig.DefaultServerConfig()
	cfg.PassphraseCommandArgv = []string{helper, marker}
	opts := &Options{
		DataDir:    root,
		Config:     cfg,
		Paths:      paths,
		IdentityID: "default",
	}

	_, _, err := ValidateAndBuildUnlockPlan(opts, &RuntimeState{}, "")
	if err == nil || !strings.Contains(err.Error(), "invalid product identity layout") {
		t.Fatalf("ValidateAndBuildUnlockPlan() error = %v, want product layout refusal", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("passphrase helper ran before layout rejection; marker stat error = %v", statErr)
	}
}

func writePassphraseHelper(t *testing.T, root, passphrase string) (string, string) {
	t.Helper()

	helper := filepath.Join(root, "passphrase-helper")
	marker := filepath.Join(root, "passphrase-helper-invoked")
	script := "#!/bin/sh\nset -eu\nprintf invoked > \"$2\"\nprintf '%s\\n' '" + passphrase + "'\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatalf("write passphrase helper: %v", err)
	}
	return helper, marker
}

func TestLoadOptionsResolvesBootstrapState(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("endpoint:\n  signer_port: 22334\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	opts, err := LoadOptions(root, "default")
	if err != nil {
		t.Fatalf("LoadOptions() error = %v", err)
	}
	if opts.DataDir != root {
		t.Fatalf("LoadOptions() data dir = %q, want %q", opts.DataDir, root)
	}
	if opts.IdentityID != "default" {
		t.Fatalf("LoadOptions() identity = %q, want %q", opts.IdentityID, "default")
	}
	if opts.Config.Endpoint.SignerPort != 22334 {
		t.Fatalf("LoadOptions() endpoint.signer_port = %d, want %d", opts.Config.Endpoint.SignerPort, 22334)
	}
}
