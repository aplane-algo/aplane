// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keystore/keystoretest"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func initializedStore(t *testing.T, passphrase []byte) storepaths.Paths {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration, DataDir: paths.Root(), Paths: paths, Role: noderole.RoleCosigner}); err != nil {
		t.Fatal(err)
	}
	return paths
}

// A lock empties the key cache with the keyring. A key load on a locked
// signer answers locked before it reaches the store: the lock destroys the
// key session first.
func TestClearKeysEmptiesTheKeyCache(t *testing.T) {
	passphrase := []byte("scan-binding-passphrase")
	paths := initializedStore(t, passphrase)
	ks := keystore.NewFileKeyStore()
	if err := keystoretest.Unlock(ks, paths, passphrase); err != nil {
		t.Fatal(err)
	}
	ks.SeedCacheForTest("ADDR", "ADDR.key")
	ks.ClearKeys()
	if got := ks.GetKeyTypes(); len(got) != 0 {
		t.Fatalf("GetKeyTypes() after a lock = %v, want the cache empty", got)
	}
}
