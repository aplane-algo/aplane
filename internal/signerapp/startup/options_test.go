// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestResolveUnlockConfigReadsProductStore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	want := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"identity-pass", "/tmp/identity"},
		PassphraseCommandEnv:  map[string]string{"IDENTITY": "1"},
	}
	if err := unlockconfig.SaveUnlockConfig(root, want); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}

	got, err := ResolveUnlockConfig(root)
	if err != nil {
		t.Fatalf("ResolveUnlockConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveUnlockConfig() = %+v, want %+v", got, want)
	}
}

func TestResolveUnlockConfigWithoutHelperIsNil(t *testing.T) {
	t.Parallel()

	got, err := ResolveUnlockConfig(t.TempDir())
	if err != nil || got != nil {
		t.Fatalf("ResolveUnlockConfig() = %+v, %v; want nil, nil", got, err)
	}
}

func TestBuildUnlockPlanLockedWithoutKeystore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	opts := &bootstrap.Startup{
		DataDir: root,
		Config:  serverconfig.DefaultServerConfig(),
		Paths:   storepaths.NewPaths(root),
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
	createAtomicStoreRootForOptionsTest(t, paths, passphrase)

	opts := &bootstrap.Startup{
		DataDir: root,
		Config:  serverconfig.DefaultServerConfig(),
		Paths:   paths,
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
	createAtomicStoreRootForOptionsTest(t, paths, passphrase)
	helper, marker := writePassphraseHelper(t, root, string(passphrase))

	cfg := serverconfig.DefaultServerConfig()
	if err := unlockconfig.SaveUnlockConfig(root, &unlockconfig.UnlockConfig{PassphraseCommandArgv: []string{helper, marker}}); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}
	opts := &bootstrap.Startup{
		DataDir: root,
		Config:  cfg,
		Paths:   paths,
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

// A startup passphrase that does not open the store root is reported as one,
// with the helper hint for an unlock.yaml helper. A store root that cannot be
// opened at all keeps its cause and gets no passphrase hint.
func TestBuildUnlockPlanReportsADamagedStoreRootApartFromAWrongPassphrase(t *testing.T) {
	t.Parallel()

	passphrase := "startup-passphrase"
	newStore := func(t *testing.T, helperReturns string) *bootstrap.Startup {
		t.Helper()
		root := t.TempDir()
		paths := storepaths.NewPaths(root)
		createAtomicStoreRootForOptionsTest(t, paths, []byte(passphrase))
		helper, marker := writePassphraseHelper(t, root, helperReturns)
		if err := unlockconfig.SaveUnlockConfig(root, &unlockconfig.UnlockConfig{PassphraseCommandArgv: []string{helper, marker}}); err != nil {
			t.Fatalf("SaveUnlockConfig() error = %v", err)
		}
		return &bootstrap.Startup{DataDir: root, Config: serverconfig.DefaultServerConfig(), Paths: paths}
	}
	damage := func(t *testing.T, opts *bootstrap.Startup) {
		t.Helper()
		rootPath := filepath.Join(opts.Paths.ProductDir(), storepaths.StoreRootName)
		if err := os.WriteFile(rootPath, []byte("not a store root"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sources := map[string]func(*bootstrap.Startup, string) error{
		"TEST_PASSPHRASE": func(opts *bootstrap.Startup, p string) error {
			_, err := BuildUnlockPlan(opts, true, p)
			return err
		},
		"helper": func(opts *bootstrap.Startup, _ string) error {
			_, err := BuildUnlockPlan(opts, true, "")
			return err
		},
	}
	for name, build := range sources {
		t.Run(name, func(t *testing.T) {
			wrong := newStore(t, "wrong-passphrase")
			err := build(wrong, "wrong-passphrase")
			if !errors.Is(err, crypto.ErrInvalidPassphrase) {
				t.Fatalf("BuildUnlockPlan(wrong passphrase) error = %v, want ErrInvalidPassphrase", err)
			}
			if name == "helper" && !strings.Contains(err.Error(), "the helper must return the store's current passphrase") {
				t.Fatalf("BuildUnlockPlan(wrong helper passphrase) error = %v, want the helper hint", err)
			}

			damaged := newStore(t, passphrase)
			damage(t, damaged)
			err = build(damaged, passphrase)
			if err == nil || errors.Is(err, crypto.ErrInvalidPassphrase) || !strings.Contains(err.Error(), "parse store root") {
				t.Fatalf("BuildUnlockPlan(damaged root) error = %v, want the store root's own cause", err)
			}
			if strings.Contains(err.Error(), "helper must return") {
				t.Fatalf("BuildUnlockPlan(damaged root) error = %v, carries the passphrase hint", err)
			}
		})
	}
}

func TestValidateAndBuildUnlockPlanRejectsExtraIdentityBeforePassphraseCommand(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	passphrase := []byte("command-passphrase")
	paths := storepaths.NewPaths(root)
	createAtomicStoreRootForOptionsTest(t, paths, passphrase)
	if err := os.MkdirAll(filepath.Join(root, "identities", "other-identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	helper, marker := writePassphraseHelper(t, root, string(passphrase))
	cfg := serverconfig.DefaultServerConfig()
	if err := unlockconfig.SaveUnlockConfig(root, &unlockconfig.UnlockConfig{PassphraseCommandArgv: []string{helper, marker}}); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}
	opts := &bootstrap.Startup{
		DataDir: root,
		Config:  cfg,
		Paths:   paths,
	}

	_, _, err := ValidateAndBuildUnlockPlan(opts, &RuntimeState{}, "")
	if err == nil || !strings.Contains(err.Error(), "invalid product-store layout") {
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

func createAtomicStoreRootForOptionsTest(t *testing.T, paths storepaths.Paths, passphrase []byte) {
	t.Helper()
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	defer kr.Zero()
	const generationID = "gen-1785200000-00000001"
	if _, err := genstore.Mint(paths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            generationID,
		FirstGeneration:         true,
		InitialPassphrase:       passphrase,
		Operation:               "test-initialize",
		OperationID:             "test-init-" + generationID,
		CreatedAt:               time.Unix(1_785_200_000, 0),
		Integrity:               kr,
		Apply:                   genstoretest.ApplyAuthorityPlaceholders,
	}); err != nil {
		t.Fatalf("Mint(atomic test store) error = %v", err)
	}
}
