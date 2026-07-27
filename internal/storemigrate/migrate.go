// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package storemigrate converts a legacy flat identity store
// (identities/<id>/{keys,keytypes}) to generation-based active storage
// (docs/ARCH_GENERATIONS.md §8). Migration is an explicit transaction run
// under the offline store lock and the identity mutation lock — never a
// startup side effect — and is crash-and-retry idempotent at every step:
//
//  1. Verify the legacy layout strictly; refuse while any Tier-1 incomplete
//     activation marker or unresolved rotation artifact exists.
//  2. Mint the first generation from independent copies of the legacy
//     namespaces (publish + durable CURRENT flip).
//  3. Bump .keystore metadata 2 -> 3 with the generations/v1 layout tag —
//     the durable layout record; every binary without generation support
//     rejects the store from this moment, before reading a stale path.
//  4. Retire the legacy namespaces into .legacy-<unix>/ (kept for a
//     documented rollback window; never deleted here).
//
// The bump is metadata-only: salt, check value, and KDF parameters are
// unchanged, so migration never needs the passphrase or master key.
package storemigrate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// legacyRetirePrefix holds the retired flat namespaces after migration.
const legacyRetirePrefix = ".legacy-"

// Result reports what one migration run did.
type Result struct {
	GenerationID string
	// AlreadyMigrated is true when the store was fully migrated before this
	// run (validated no-op).
	AlreadyMigrated bool
	// ResumedAfterCrash is true when this run finished a migration a crash
	// interrupted (e.g. CURRENT flipped but the version bump was lost).
	ResumedAfterCrash bool
	// RetiredDir holds the legacy namespaces ("" when none remained).
	RetiredDir string
}

// Migrate converts one identity store. The caller holds the offline store
// lock and the identity mutation lock; the daemon must not be running.
func Migrate(paths storepaths.Paths, identityID string, now time.Time) (Result, error) {
	var result Result

	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		return result, fmt.Errorf("migrate: %w", err)
	}
	if meta == nil {
		return result, fmt.Errorf("migrate: store is not initialized (missing .keystore)")
	}

	generational, err := genstore.IsGenerational(paths, identityID)
	if err != nil {
		return result, err
	}

	switch {
	case generational && meta.Version >= crypto.GenerationalKeystoreMetadataVersion:
		// Fully migrated: validate and retire any legacy leftovers.
		gen, err := genstore.Resolve(paths, identityID)
		if err != nil {
			return result, fmt.Errorf("migrate: migrated store: %w", err)
		}
		if err := genstore.ValidateCurrent(gen); err != nil {
			return result, fmt.Errorf("migrate: migrated store: %w", err)
		}
		result.GenerationID = gen.GenerationID()
		result.AlreadyMigrated = true
		retired, err := retireLegacyNamespaces(paths, identityID, now)
		if err != nil {
			return result, err
		}
		result.RetiredDir = retired
		return result, nil

	case generational:
		// Crash window: CURRENT flipped, version bump lost. Finish it.
		gen, err := genstore.Resolve(paths, identityID)
		if err != nil {
			return result, fmt.Errorf("migrate: interrupted migration: %w", err)
		}
		if err := genstore.ValidateCurrent(gen); err != nil {
			return result, fmt.Errorf("migrate: interrupted migration: %w", err)
		}
		result.GenerationID = gen.GenerationID()
		result.ResumedAfterCrash = true
		if err := bumpKeystoreLayoutVersion(paths, identityID, meta); err != nil {
			return result, err
		}
		retired, err := retireLegacyNamespaces(paths, identityID, now)
		if err != nil {
			return result, err
		}
		result.RetiredDir = retired
		return result, nil
	}

	// Legacy store: verify fully, refuse unresolved state, then convert.
	// The metadata bump is dry-run validated first: nothing may flip
	// CURRENT unless the layout record that follows it is guaranteed to
	// write (a v1 record persists its legacy KDF constants at this point).
	if _, err := crypto.GenerationalMetadataFrom(meta); err != nil {
		return result, fmt.Errorf("migrate: keystore metadata cannot carry the layout version: %w", err)
	}
	if err := verifyLegacyLayout(paths, identityID); err != nil {
		return result, err
	}
	incomplete, err := recovered.IncompleteActivationIDs(paths, identityID)
	if err != nil {
		return result, fmt.Errorf("migrate: inspect activation state: %w", err)
	}
	if len(incomplete) > 0 {
		return result, fmt.Errorf(
			"migrate: %d incomplete activation(s) must be resolved first (resume or roll back): %s",
			len(incomplete), strings.Join(incomplete, ", "))
	}

	generationID, err := genstore.NewGenerationID(now)
	if err != nil {
		return result, err
	}
	if _, err := genstore.Mint(paths, identityID, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "layout-migration",
		OperationID:     "migrate-" + generationID,
		CreatedAt:       now,
		Apply: func(staged storepaths.GenPaths) error {
			return copyLegacyNamespaces(paths, identityID, staged)
		},
	}); err != nil {
		return result, fmt.Errorf("migrate: %w", err)
	}
	result.GenerationID = generationID

	if err := bumpKeystoreLayoutVersion(paths, identityID, meta); err != nil {
		return result, err
	}
	retired, err := retireLegacyNamespaces(paths, identityID, now)
	if err != nil {
		return result, err
	}
	result.RetiredDir = retired
	return result, nil
}

// verifyLegacyLayout strictly checks the flat namespaces: regular
// directories holding only regular files, and no unresolved rotation
// artifacts (.new/.old siblings from an interrupted changepass).
func verifyLegacyLayout(paths storepaths.Paths, identityID string) error {
	for _, dir := range []string{paths.KeysDir(identityID), paths.KeyTypeRecordsDir(identityID)} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue // an empty store may lack a namespace entirely
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("migrate: legacy namespace is not a regular directory: %s", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				return fmt.Errorf("migrate: legacy namespace entry is not a regular file: %s",
					filepath.Join(dir, entry.Name()))
			}
			if strings.HasSuffix(entry.Name(), ".new") || strings.HasSuffix(entry.Name(), ".old") {
				return fmt.Errorf(
					"migrate: unresolved passphrase-rotation artifact %s; run or roll back the rotation first",
					filepath.Join(dir, entry.Name()))
			}
		}
	}
	return nil
}

func copyLegacyNamespaces(paths storepaths.Paths, identityID string, staged storepaths.GenPaths) error {
	namespaces := map[string]string{
		paths.KeysDir(identityID):           staged.KeysDir(),
		paths.KeyTypeRecordsDir(identityID): staged.KeyTypeRecordsDir(),
	}
	for src, dst := range namespaces {
		entries, err := os.ReadDir(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			data, mode, err := fsutil.ReadRegularFile(filepath.Join(src, entry.Name()))
			if err != nil {
				return fmt.Errorf("copy legacy %s: %w", entry.Name(), err)
			}
			if err := os.WriteFile(filepath.Join(dst, entry.Name()), data, mode.Perm()); err != nil {
				return err
			}
		}
	}
	return nil
}

// bumpKeystoreLayoutVersion durably records the layout change in .keystore.
// A .keystore.premigration copy is kept beside it for the documented manual
// downgrade path. Idempotent: a v3 metadata file is left untouched.
func bumpKeystoreLayoutVersion(paths storepaths.Paths, identityID string, meta *crypto.KeystoreMetadata) error {
	if meta.Version >= crypto.GenerationalKeystoreMetadataVersion {
		return nil
	}
	metadataDir := paths.KeystoreMetadataDir(identityID)
	keystorePath := filepath.Join(metadataDir, ".keystore")
	original, _, err := fsutil.ReadRegularFile(keystorePath)
	if err != nil {
		return fmt.Errorf("migrate: read keystore metadata: %w", err)
	}
	backupPath := keystorePath + ".premigration"
	if _, err := os.Lstat(backupPath); os.IsNotExist(err) {
		if err := fsutil.WriteFileDurable(backupPath, original); err != nil {
			return fmt.Errorf("migrate: write downgrade backup: %w", err)
		}
	}
	bumped, err := crypto.GenerationalMetadataFrom(meta)
	if err != nil {
		return err
	}
	data, err := crypto.MarshalKeystoreMetadata(bumped)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(keystorePath, data); err != nil {
		return fmt.Errorf("migrate: record layout version: %w", err)
	}
	return nil
}

// retireLegacyNamespaces moves any remaining flat keys/ and keytypes/ into
// .legacy-<unix>/ inside the identity directory (same filesystem). They are
// kept for a documented rollback window and never deleted here.
func retireLegacyNamespaces(paths storepaths.Paths, identityID string, now time.Time) (string, error) {
	identityDir := paths.IdentityDir(identityID)
	var retireDir string
	for _, namespace := range []string{"keys", "keytypes"} {
		src := filepath.Join(identityDir, namespace)
		if _, err := os.Lstat(src); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return retireDir, err
		}
		if retireDir == "" {
			retireDir = filepath.Join(identityDir, fmt.Sprintf("%s%d", legacyRetirePrefix, now.Unix()))
			if err := os.MkdirAll(retireDir, 0o770); err != nil {
				return "", err
			}
		}
		dst := filepath.Join(retireDir, namespace)
		if err := os.Rename(src, dst); err != nil {
			return retireDir, fmt.Errorf("migrate: retire legacy %s: %w", namespace, err)
		}
	}
	if retireDir != "" {
		if err := fsutil.SyncDir(identityDir); err != nil {
			return retireDir, err
		}
	}
	return retireDir, nil
}
