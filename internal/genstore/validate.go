// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The strict generation validator is fail-closed and deliberately NOT the
// tolerant runtime reload: FileKeyStore.Scan records recoverable warnings
// and still succeeds, and reload audits rejected keys rather than failing —
// those semantics cannot back "selected generation fails validation →
// recovery". Content-level (decryption) validation happens at reload with
// the master key; everything structural and digest-shaped is enforced here.

// ValidateCurrent structurally validates the generation CURRENT selects:
// manifest present, schema-valid, and complete; only permitted entries in
// the generation directory; namespaces are regular directories holding only
// regular files. At-mint inventory equality is deliberately NOT required —
// the current generation is mutable through durable single-file operations
// — and any stale seal is ignored for the same reason.
func ValidateCurrent(gen storepaths.GenPaths) error {
	if err := validateStructure(gen); err != nil {
		return err
	}
	manifest, err := ReadManifest(gen)
	if err != nil {
		return err
	}
	if !manifest.Complete {
		return fmt.Errorf("generation %s manifest is not complete", gen.GenerationID())
	}
	return nil
}

// ValidateSealed validates a non-current generation against its final seal:
// full inventory and digest equality. The at-mint manifest is not the
// content authority for a generation that was mutable while current; the
// seal is. This is the integrity check rollback targets depend on. A prior
// generation with no seal fails here — the seal precedes every flip.
func ValidateSealed(gen storepaths.GenPaths) error {
	if err := validateStructure(gen); err != nil {
		return err
	}
	manifest, err := ReadManifest(gen)
	if err != nil {
		return err
	}
	if !manifest.Complete {
		return fmt.Errorf("generation %s manifest is not complete", gen.GenerationID())
	}
	seal, err := ReadSeal(gen)
	if err != nil {
		return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
	}
	live, err := BuildInventory(gen)
	if err != nil {
		return err
	}
	if !slices.Equal(live, seal.Inventory) {
		return fmt.Errorf("generation %s content does not match its seal", gen.GenerationID())
	}
	return nil
}

// VerifyFileAgainstSeal checks one namespace-relative path ("keys/X.key")
// against a loaded seal.
func VerifyFileAgainstSeal(gen storepaths.GenPaths, seal *Seal, relativePath string) error {
	index := slices.IndexFunc(seal.Inventory, func(e InventoryEntry) bool {
		return e.Path == relativePath
	})
	if index < 0 {
		return fmt.Errorf("%s is not in generation %s's seal", relativePath, gen.GenerationID())
	}
	data, _, err := fsutil.ReadRegularFile(filepath.Join(gen.Dir(), filepath.FromSlash(relativePath)))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != seal.Inventory[index].SHA256 {
		return fmt.Errorf("%s does not match generation %s's seal", relativePath, gen.GenerationID())
	}
	return nil
}

// validateStructure enforces the generation directory's shape: a regular
// directory containing only manifest.json, seal.json, and the namespace
// directories; namespaces contain only regular files; no symlinks anywhere.
func validateStructure(gen storepaths.GenPaths) error {
	if err := requireRegularDirectory(gen.Dir()); err != nil {
		return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
	}
	entries, err := os.ReadDir(gen.Dir())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == storepaths.GenerationManifestName || name == storepaths.GenerationSealName:
			if _, _, err := fsutil.ReadRegularFile(filepath.Join(gen.Dir(), name)); err != nil {
				return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
			}
		case slices.Contains(generationNamespaces, name):
			if err := validateNamespaceDir(filepath.Join(gen.Dir(), name)); err != nil {
				return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
			}
		default:
			return fmt.Errorf("generation %s contains unsupported entry %q", gen.GenerationID(), name)
		}
	}
	return nil
}

func validateNamespaceDir(dir string) error {
	if err := requireRegularDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("namespace entry is not a regular file: %s", filepath.Join(dir, entry.Name()))
		}
	}
	return nil
}
