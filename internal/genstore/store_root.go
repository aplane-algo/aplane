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
// consulting CURRENT. The caller owns the returned keyring and must Zero it.
func ResolveStoreRoot(
	paths storepaths.Paths,
	passphrase []byte,
) (storepaths.GenPaths, *crypto.Keyring, error) {
	kr, selection, err := crypto.OpenStoreRootStore(paths.KeystoreMetadataDir(), passphrase)
	if err != nil {
		return storepaths.GenPaths{}, nil, err
	}
	success := false
	defer func() {
		if !success {
			kr.Zero()
		}
	}()
	gen := paths.GenerationPaths(selection.CurrentGenerationID)
	if err := requireRegularDirectory(gen.Dir()); err != nil {
		return storepaths.GenPaths{}, nil, fmt.Errorf("store root selected generation: %w", err)
	}
	if err := ValidateCurrent(gen); err != nil {
		return storepaths.GenPaths{}, nil, fmt.Errorf("store root selected generation: %w", err)
	}
	success = true
	return gen, kr, nil
}
