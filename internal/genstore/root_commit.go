// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var (
	// ErrStoreRootCommitDurabilityUnknown means the candidate root is visible
	// after a failed durable replacement. Callers must enter recovery; a blind
	// retry could overwrite the only evidence of which authority was selected.
	ErrStoreRootCommitDurabilityUnknown = errors.New("store root commit durability is unknown")
	// ErrStoreRootCommitStateUnknown means neither the old nor candidate exact
	// root could be proven after a write failure.
	ErrStoreRootCommitStateUnknown = errors.New("store root commit state is unknown")
)

// CommitStoreRoot performs an ordinary generation selection. It takes a fresh
// exact read after successor publication/sealing, authenticates its outgoing
// generation under kr, preserves its wrapped keyring bytes exactly, and
// replaces the sole root record once.
func CommitStoreRoot(
	paths storepaths.Paths,
	kr *crypto.Keyring,
	expectedCurrentGenerationID string,
	newGenerationID string,
) error {
	if err := storepaths.ValidateGenerationID(expectedCurrentGenerationID); err != nil {
		return err
	}
	if err := validateStoreRootCommitTarget(paths, newGenerationID); err != nil {
		return err
	}
	if err := ValidateSealed(paths.GenerationPaths(expectedCurrentGenerationID), kr); err != nil {
		return fmt.Errorf(
			"outgoing generation %s is not durably sealed: %w",
			expectedCurrentGenerationID,
			err,
		)
	}
	exact, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil {
		return err
	}
	selection, err := crypto.AuthenticateStoreRoot(exact, kr)
	if err != nil {
		return fmt.Errorf("authenticate current store root: %w", err)
	}
	if selection.CurrentGenerationID != expectedCurrentGenerationID {
		return fmt.Errorf(
			"store root current generation %s does not match expected outgoing generation %s",
			selection.CurrentGenerationID,
			expectedCurrentGenerationID,
		)
	}
	candidate, err := crypto.ReselectStoreRoot(exact, kr, newGenerationID)
	if err != nil {
		return fmt.Errorf("build store root candidate: %w", err)
	}
	return replaceStoreRootClassified(paths, exact, candidate)
}

// CommitInitialStoreRoot publishes the first root only after the first
// generation is complete. It refuses every retired layout artifact; the only
// accepted retry state is a v6 marker with no visible root.
func CommitInitialStoreRoot(
	paths storepaths.Paths,
	kr *crypto.Keyring,
	passphrase []byte,
	generationID string,
) error {
	if err := validateStoreRootCommitTarget(paths, generationID); err != nil {
		return err
	}
	for _, retired := range []string{
		paths.CurrentPointerPath(),
		crypto.KeyringPath(paths.KeystoreMetadataDir()),
	} {
		if _, err := os.Lstat(retired); err == nil {
			return fmt.Errorf("refusing atomic store-root initialization over retired layout artifact %s", retired)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := crypto.InitializeStoreRootMarker(paths.KeystoreMetadataDir()); err != nil {
		return err
	}
	rootPath := paths.StoreRootPath()
	if _, err := os.Lstat(rootPath); err == nil {
		return fmt.Errorf("store root already exists: %s", rootPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	candidate, err := crypto.SealStoreRoot(kr, passphrase, generationID)
	if err != nil {
		return err
	}
	return replaceStoreRootClassified(paths, nil, candidate)
}

func validateStoreRootCommitTarget(paths storepaths.Paths, generationID string) error {
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return err
	}
	gen := paths.GenerationPaths(generationID)
	if err := requireRegularDirectory(gen.Dir()); err != nil {
		return fmt.Errorf("store root target %s: %w", generationID, err)
	}
	if err := ValidateCurrent(gen); err != nil {
		return fmt.Errorf("store root target %s: %w", generationID, err)
	}
	return nil
}

func replaceStoreRootClassified(
	paths storepaths.Paths,
	previous, candidate []byte,
) error {
	writeErr := fsutil.WriteFileDurable(paths.StoreRootPath(), candidate)
	if writeErr == nil {
		return nil
	}
	visible, readErr := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	switch {
	case readErr == nil && bytes.Equal(visible, candidate):
		return fmt.Errorf("%w: %v", ErrStoreRootCommitDurabilityUnknown, writeErr)
	case readErr == nil && previous != nil && bytes.Equal(visible, previous):
		return writeErr
	case readErr != nil && previous == nil && errors.Is(readErr, os.ErrNotExist):
		return writeErr
	case readErr != nil:
		return fmt.Errorf(
			"%w: write: %v; classify visible root: %v",
			ErrStoreRootCommitStateUnknown,
			writeErr,
			readErr,
		)
	default:
		return fmt.Errorf(
			"%w: visible root matches neither old nor candidate",
			ErrStoreRootCommitStateUnknown,
		)
	}
}
