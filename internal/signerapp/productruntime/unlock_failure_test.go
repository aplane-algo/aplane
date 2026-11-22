// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Only a passphrase that does not open the store root is reported as an
// invalid passphrase. A store root the right passphrase cannot open, here one
// that no longer parses, is a failed unlock that keeps its cause, for both
// an unlock from locked and one from recovery.
func TestUnlockReportsADamagedStoreRootApartFromAWrongPassphrase(t *testing.T) {
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("unlock-failure-passphrase")
	if _, err := storeinit.Initialize(append([]byte(nil), passphrase...), storeinit.Options{
		ValidateCandidate: func(storeinit.FirstGenerationCandidate) error { return nil },
		DataDir:           root,
		Paths:             paths,
	}); err != nil {
		t.Fatal(err)
	}
	ir := New(Config{KeyStore: keystore.NewAtomicFileKeyStoreForPaths(paths), KeyPaths: paths})
	reconcile := func(*crypto.Keyring) error { return nil }
	attempts := map[string]func([]byte) error{
		"unlock from locked": func(p []byte) error {
			ir.Lock()
			_, err := ir.Unlock(p, reconcile, nil)
			return err
		},
		"unlock from recovery": func(p []byte) error {
			ir.SetUnlocked()
			ir.SetRecovery()
			_, err := ir.Unlock(p, reconcile, nil)
			return err
		},
	}

	for name, try := range attempts {
		if err := try([]byte("wrong passphrase")); !errors.Is(err, crypto.ErrInvalidPassphrase) || err.Error() != "invalid passphrase" {
			t.Fatalf("%s with a wrong passphrase = %v, want invalid passphrase", name, err)
		}
	}

	rootPath := filepath.Join(paths.ProductDir(), storepaths.StoreRootName)
	if err := os.WriteFile(rootPath, []byte("not a store root"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, try := range attempts {
		err := try(passphrase)
		if err == nil || errors.Is(err, crypto.ErrInvalidPassphrase) || !strings.Contains(err.Error(), "parse store root") {
			t.Fatalf("%s of a damaged store root = %v, want a failure that names the cause", name, err)
		}
	}
}
