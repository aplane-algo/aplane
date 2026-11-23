// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keystoretest sets up a keystore for tests the way a publish does,
// without a runtime: open the keyring from the store root, scan what the
// root selects, and install the result.
package keystoretest

import (
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Unlock opens ks's keyring from the store root at paths with passphrase
// and installs it, bound to the generation the root selects and with no
// keys, as an unlock's publish installs a keyring. It zeroes the keyring it
// replaced.
func Unlock(ks *keystore.FileKeyStore, paths storepaths.Paths, passphrase []byte) error {
	selection, kr, err := genstore.OpenStoreRootSelection(paths, passphrase)
	if err != nil {
		return err
	}
	ks.Install(kr, keystore.Contents{Selection: &selection}).ZeroWhenUnused()
	return nil
}

// Rescan scans the generation the store root at paths selects with ks's
// keyring and installs what it finds, as a reload's publish does, and returns
// the scan. The keyring stays.
func Rescan(ks *keystore.FileKeyStore, paths storepaths.Paths) (keystore.Contents, error) {
	var kr *crypto.Keyring
	var contents keystore.Contents
	var scanErr error
	if err := ks.WithKeyring(func(inService *crypto.Keyring) error {
		kr = inService
		selection, err := genstore.AuthenticateStoreRootSelection(paths, inService)
		if err != nil {
			scanErr = err
			return nil
		}
		contents, scanErr = keystore.ScanGeneration(selection, inService)
		return nil
	}); err != nil {
		return keystore.Contents{}, err
	}
	if scanErr != nil {
		return contents, scanErr
	}
	ks.Install(kr, contents).ZeroWhenUnused()
	return contents, nil
}
