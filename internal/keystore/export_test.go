// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
)

// setKeyringForTest installs a single-term keyring holding key, standing in
// for the unlock a real store performs against store-root.enc. It exists so tests
// can reach the locked state without a passphrase or an on-disk root.
func (f *FileKeyStore) setKeyringForTest(key []byte) error {
	kr, err := crypto.NewKeyringFromKey(key)
	if err != nil {
		return err
	}
	f.setKeyringDirectlyForTest(kr)
	return nil
}

// setKeyringDirectlyForTest installs an already-open keyring.
func (f *FileKeyStore) setKeyringDirectlyForTest(kr *crypto.Keyring) {
	f.cacheLock.Lock()
	previous := f.replaceKeyringLocked(kr)
	f.cacheLock.Unlock()
	previous.ZeroWhenUnused()
}

// keyringIsLoaded reports whether a keyring is resident.
func (f *FileKeyStore) keyringIsLoaded() bool {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return f.keyring != nil
}

// contentsForTest reads the keyring, the binding, the key cache and the
// warnings under one hold of the cache lock, as one reader of the store sees
// them.
func (f *FileKeyStore) contentsForTest() (kr *crypto.Keyring, generation string, files map[string]string, warnings int) {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	if f.active != nil {
		generation = f.active.GenerationID()
	}
	return f.keyring, generation, Contents{Keys: f.cache}.KeyFiles(), len(f.scanWarnings)
}

// SeedCacheForTest puts one cached key for address on the store, as a scan
// that found it would have.
func (f *FileKeyStore) SeedCacheForTest(address, keyFile string) {
	f.cacheLock.Lock()
	defer f.cacheLock.Unlock()
	f.cache = map[string]keys.KeyScanInfo{address: {KeyFile: keyFile}}
}
