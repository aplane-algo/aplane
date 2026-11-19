// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Only a passphrase that does not open the store root is reported as an
// invalid passphrase. A store root the right passphrase cannot open, here one
// that no longer parses, is a failed unlock that keeps its cause, for both
// the unlock and the recovery unlock.
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
	attempts := map[string]func([]byte) (bool, string){
		"unlock": func(p []byte) (bool, string) {
			ok, _, msg := ir.TryUnlock(p, nil)
			return ok, msg
		},
		"recovery unlock": ir.TryRecoveryUnlock,
	}

	for name, try := range attempts {
		if ok, msg := try([]byte("wrong passphrase")); ok || msg != InvalidPassphraseMessage {
			t.Fatalf("%s with a wrong passphrase = (%t, %q), want %q", name, ok, msg, InvalidPassphraseMessage)
		}
	}

	rootPath := filepath.Join(paths.KeystoreMetadataDir(), storepaths.StoreRootName)
	if err := os.WriteFile(rootPath, []byte("not a store root"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, try := range attempts {
		ok, msg := try(passphrase)
		if ok || msg == InvalidPassphraseMessage || !strings.Contains(msg, "parse store root") {
			t.Fatalf("%s of a damaged store root = (%t, %q), want a failure that names the cause", name, ok, msg)
		}
	}
}
