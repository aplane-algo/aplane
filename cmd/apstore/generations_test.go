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
	"github.com/aplane-algo/aplane/internal/storemigrate"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// newGenerationalTestStore builds a real migrated store: legacy layout plus
// v2 metadata, converted through the production migration path.
func newGenerationalTestStore(t *testing.T, passphrase string) (storepaths.Paths, string) {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	for _, dir := range []string{paths.KeysDir(identityID), paths.KeyTypeRecordsDir(identityID)} {
		if err := fsutil.MkdirAll(dir); err != nil {
			t.Fatalf("MkdirAll(%s): %v", dir, err)
		}
	}
	if _, _, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), []byte(passphrase)); err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	if _, err := storemigrate.Migrate(paths, identityID, time.Unix(1_785_100_000, 0)); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return paths, identityID
}

func TestVerifyCurrentGenerationContentPassesOnCleanStore(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "prune-pass")
	paths, identityID := newGenerationalTestStore(t, "prune-pass")

	if err := verifyCurrentGenerationContent(paths, identityID); err != nil {
		t.Fatalf("verifyCurrentGenerationContent() error = %v, want clean pass", err)
	}
}

func TestVerifyCurrentGenerationContentRejectsWrongPassphrase(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "wrong-pass")
	paths, identityID := newGenerationalTestStore(t, "prune-pass")

	err := verifyCurrentGenerationContent(paths, identityID)
	if err == nil || !strings.Contains(err.Error(), "passphrase verification failed") {
		t.Fatalf("verifyCurrentGenerationContent() error = %v, want passphrase rejection", err)
	}
}

func TestVerifyCurrentGenerationContentFailsOnMalformedKey(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "prune-pass")
	paths, identityID := newGenerationalTestStore(t, "prune-pass")

	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	garbage := filepath.Join(active.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not encrypted"), 0o600); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}

	err = verifyCurrentGenerationContent(paths, identityID)
	if err == nil || !strings.Contains(err.Error(), "refusing to prune") {
		t.Fatalf("verifyCurrentGenerationContent() error = %v, want content rejection", err)
	}
}
