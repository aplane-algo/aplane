// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import "github.com/aplane-algo/aplane/internal/crypto"

// setKeyringForTest installs a single-term keyring holding key, standing in
// for the unlock a real store performs against store-root.enc. It exists so tests
// can reach the locked state without a passphrase or an on-disk root.
func (f *FileKeyStore) setKeyringForTest(key []byte) error {
	kr, err := crypto.NewKeyringFromKey(key)
	if err != nil {
		return err
	}
	f.cacheLock.Lock()
	defer f.cacheLock.Unlock()
	if f.keyring != nil {
		f.keyring.Zero()
	}
	f.keyring = kr
	return nil
}

// setKeyringDirectlyForTest installs an already-open keyring.
func (f *FileKeyStore) setKeyringDirectlyForTest(kr *crypto.Keyring) {
	f.cacheLock.Lock()
	defer f.cacheLock.Unlock()
	if f.keyring != nil {
		f.keyring.Zero()
	}
	f.keyring = kr
}

// keyringIsLoaded reports whether a keyring is resident.
func (f *FileKeyStore) keyringIsLoaded() bool {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return f.keyring != nil
}
