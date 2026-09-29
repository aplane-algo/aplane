// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// newGenerationalTestStore builds the atomic-root generation layout.
func newGenerationalTestStore(t *testing.T, passphrase string) storepaths.Paths {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_100_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID:      generationID,
		FirstGeneration:   true,
		InitialPassphrase: []byte(passphrase),
		Integrity:         kr,
		Operation:         "store-initialize",
		OperationID:       "init-" + generationID,
		CreatedAt:         time.Unix(1_785_100_000, 0),
		Apply:             genstoretest.ApplyAuthorityPlaceholders,
	}); err != nil {
		t.Fatalf("Mint(first) error = %v", err)
	}
	return paths
}

func TestVerifyCurrentGenerationContentPassesOnCleanStore(t *testing.T) {
	paths := newGenerationalTestStore(t, "prune-pass")
	active, kr, err := genstore.ResolveStoreRoot(paths, []byte("prune-pass"))
	if err != nil {
		t.Fatalf("ResolveStoreRoot() error = %v", err)
	}
	defer kr.Zero()

	if err := verifyCurrentGenerationContentWithKeyring(paths, active, kr); err != nil {
		t.Fatalf("verifyCurrentGenerationContentWithKeyring() error = %v, want clean pass", err)
	}
}

func TestVerifyCurrentGenerationContentFailsOnMalformedKey(t *testing.T) {
	paths := newGenerationalTestStore(t, "prune-pass")
	active, kr, err := genstore.ResolveStoreRoot(paths, []byte("prune-pass"))
	if err != nil {
		t.Fatalf("ResolveStoreRoot() error = %v", err)
	}
	defer kr.Zero()

	garbage := filepath.Join(active.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not encrypted"), 0o600); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}

	err = verifyCurrentGenerationContentWithKeyring(paths, active, kr)
	if err == nil || !strings.Contains(err.Error(), "refusing to prune") {
		t.Fatalf("verifyCurrentGenerationContentWithKeyring() error = %v, want content rejection", err)
	}
}

func TestVerifyCurrentGenerationContentRejectsSymlinkedNamespaceBeforePrompt(t *testing.T) {
	// APSIGNER_PASSPHRASE deliberately unset and no stdin provided: the
	// structural rejection must happen before any passphrase prompt or
	// content read could follow the symlink.
	t.Setenv("APSIGNER_PASSPHRASE", "")
	paths := newGenerationalTestStore(t, "prune-pass")

	active, kr, err := genstore.ResolveStoreRoot(paths, []byte("prune-pass"))
	if err != nil {
		t.Fatalf("ResolveStoreRoot() error = %v", err)
	}
	kr.Zero()
	outside := filepath.Join(t.TempDir(), "outside-keys")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("MkdirAll(outside): %v", err)
	}
	if err := os.RemoveAll(active.KeysDir()); err != nil {
		t.Fatalf("remove keys namespace: %v", err)
	}
	if err := os.Symlink(outside, active.KeysDir()); err != nil {
		t.Fatalf("symlink keys namespace: %v", err)
	}

	err = validateCurrentGenerationForContent(active)
	if err == nil || !strings.Contains(err.Error(), "current generation failed validation") {
		t.Fatalf("validateCurrentGenerationForContent() error = %v, want structural rejection", err)
	}
}

func TestParsePruneArgs(t *testing.T) {
	tests := []struct {
		args    []string
		want    pruneOptions
		wantErr string
	}{
		{args: nil, want: pruneOptions{}},
		{args: []string{"--all-priors"}, want: pruneOptions{allPriors: true}},
		{args: []string{"--yes"}, want: pruneOptions{assumeYes: true}},
		{args: []string{"--all-priors", "--yes"}, want: pruneOptions{allPriors: true, assumeYes: true}},
		{args: []string{"--yes", "--all-priors"}, want: pruneOptions{allPriors: true, assumeYes: true}},
		{args: []string{"--yes", "--yes"}, wantErr: "duplicate prune option --yes"},
		{args: []string{"-y"}, wantErr: generationsPruneUsage},
		{args: []string{"--force"}, wantErr: generationsPruneUsage},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			got, err := parsePruneArgs(test.args)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parsePruneArgs(%q) error = %v, want %q", test.args, err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("parsePruneArgs(%q) = %+v, %v; want %+v", test.args, got, err, test.want)
			}
		})
	}
}

// Unattended prune (cron/CI/provisioning) has no stdin; --yes must replace
// the interactive confirmation while the prompt path still defaults to no.
func TestGenerationsPruneUnattended(t *testing.T) {
	for _, args := range [][]string{
		{"prune", "--yes"},
		{"prune", "--all-priors", "--yes"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			paths := newGenerationalTestStore(t, "prune-pass")
			oldDataDirectory := dataDirectory
			dataDirectory = paths.Root()
			t.Cleanup(func() { dataDirectory = oldDataDirectory })
			t.Setenv("APSIGNER_PASSPHRASE", "prune-pass")

			if err := withTestStdin("", func() error { return cmdGenerations(args) }); err != nil {
				t.Fatalf("cmdGenerations(%q) with empty stdin error = %v", args, err)
			}

			withoutYes := args[:len(args)-1]
			err := withTestStdin("", func() error { return cmdGenerations(withoutYes) })
			if err == nil || !strings.Contains(err.Error(), "prune cancelled") {
				t.Fatalf("cmdGenerations(%q) with empty stdin error = %v, want prune cancelled", withoutYes, err)
			}
		})
	}
}
