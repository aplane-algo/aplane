// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// ResolveStoreRoot is the read-only resolution path for the gated atomic-root
// layout. It authenticates the wrapped keyring and generation selection from
// the same exact root, then validates the selected generation without
// consulting a public pointer. The caller owns the returned keyring and must Zero it.
func ResolveStoreRoot(
	paths storepaths.Paths,
	passphrase []byte,
) (storepaths.GenPaths, *crypto.Keyring, error) {
	gen, kr, err := OpenStoreRootSelection(paths, passphrase)
	if err != nil {
		return storepaths.GenPaths{}, nil, err
	}
	success := false
	defer func() {
		if !success {
			kr.Zero()
		}
	}()
	if err := validateStoreRootSelectionTarget(gen); err != nil {
		return storepaths.GenPaths{}, nil, err
	}
	success = true
	return gen, kr, nil
}

// OpenStoreRootSelection authenticates the sole root and returns its selected
// generation handle without validating generation contents. Recovery unlock
// uses this separation: a correct passphrase and root may enter recovery even
// when the selected generation is damaged or absent.
func OpenStoreRootSelection(
	paths storepaths.Paths,
	passphrase []byte,
) (storepaths.GenPaths, *crypto.Keyring, error) {
	kr, selection, err := crypto.OpenStoreRootStore(paths.KeystoreMetadataDir(), passphrase)
	if err != nil {
		return storepaths.GenPaths{}, nil, err
	}
	gen := paths.GenerationPaths(selection.CurrentGenerationID)
	return gen, kr, nil
}

func validateStoreRootSelectionTarget(gen storepaths.GenPaths) error {
	if err := requireRegularDirectory(gen.Dir()); err != nil {
		return fmt.Errorf("store root selected generation: %w", err)
	}
	if err := ValidateCurrent(gen); err != nil {
		return fmt.Errorf("store root selected generation: %w", err)
	}
	return nil
}

// ResolveStoreRootWithKeyring authenticates a fresh exact root read with an
// already-open keyring and validates the selected generation. Runtime reload
// and mutation paths use it so selection is never taken from an unauthenticated
// public projection or a stale cached generation ID.
func ResolveStoreRootWithKeyring(
	paths storepaths.Paths,
	kr *crypto.Keyring,
) (storepaths.GenPaths, error) {
	exact, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil {
		return storepaths.GenPaths{}, err
	}
	selection, err := crypto.AuthenticateStoreRoot(exact, kr)
	if err != nil {
		return storepaths.GenPaths{}, fmt.Errorf("authenticate store root: %w", err)
	}
	gen := paths.GenerationPaths(selection.CurrentGenerationID)
	if err := validateStoreRootSelectionTarget(gen); err != nil {
		return storepaths.GenPaths{}, err
	}
	return gen, nil
}
