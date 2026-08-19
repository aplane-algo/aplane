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
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// newGenerationalTestStore builds a generational store the way initialize
// does: v3 metadata first, then the authorized first mint.
func newGenerationalTestStore(t *testing.T, passphrase string) (storepaths.Paths, string) {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	if err := fsutil.MkdirAll(paths.KeystoreMetadataDir()); err != nil {
		t.Fatalf("MkdirAll(metadata): %v", err)
	}
	if _, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), []byte(passphrase)); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_100_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-initialize",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_785_100_000, 0),
	}); err != nil {
		t.Fatalf("Mint(first) error = %v", err)
	}
	return paths, identityID
}

func TestVerifyCurrentGenerationContentPassesOnCleanStore(t *testing.T) {
	paths, identityID := newGenerationalTestStore(t, "prune-pass")
	kr, err := crypto.OpenKeyringStore(
		paths.KeystoreMetadataDir(),
		[]byte("prune-pass"),
	)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()

	if err := verifyCurrentGenerationContentWithKeyring(paths, identityID, kr); err != nil {
		t.Fatalf("verifyCurrentGenerationContentWithKeyring() error = %v, want clean pass", err)
	}
}

func TestVerifyCurrentGenerationContentFailsOnMalformedKey(t *testing.T) {
	paths, identityID := newGenerationalTestStore(t, "prune-pass")
	kr, err := crypto.OpenKeyringStore(
		paths.KeystoreMetadataDir(),
		[]byte("prune-pass"),
	)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()

	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	garbage := filepath.Join(active.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not encrypted"), 0o600); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}

	err = verifyCurrentGenerationContentWithKeyring(paths, identityID, kr)
	if err == nil || !strings.Contains(err.Error(), "refusing to prune") {
		t.Fatalf("verifyCurrentGenerationContentWithKeyring() error = %v, want content rejection", err)
	}
}

func TestVerifyCurrentGenerationContentRejectsSymlinkedNamespaceBeforePrompt(t *testing.T) {
	// APSIGNER_PASSPHRASE deliberately unset and no stdin provided: the
	// structural rejection must happen before any passphrase prompt or
	// content read could follow the symlink.
	t.Setenv("APSIGNER_PASSPHRASE", "")
	paths, identityID := newGenerationalTestStore(t, "prune-pass")

	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
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

	err = validateCurrentGenerationForContent(paths, identityID)
	if err == nil || !strings.Contains(err.Error(), "current generation failed validation") {
		t.Fatalf("validateCurrentGenerationForContent() error = %v, want structural rejection", err)
	}
}
