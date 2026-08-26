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
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The strict generation validator is fail-closed and deliberately NOT the
// tolerant runtime reload: FileKeyStore.Scan records recoverable warnings
// and still succeeds, and reload audits rejected keys rather than failing —
// those semantics cannot back "selected generation fails validation →
// recovery". Content-level (decryption) validation happens at reload with
// the keyring; everything structural and digest-shaped is enforced here.

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
	if _, err := InspectDeletedArchive(gen); err != nil {
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

// ValidateSealed validates a non-current generation against its authenticated
// final seal: exact manifest binding plus full inventory and digest equality.
// The at-mint manifest is not the
// content authority for a generation that was mutable while current; the
// seal is. This is the integrity check rollback targets depend on. A prior
// generation with no seal fails here — the seal precedes every flip.
func ValidateSealed(gen storepaths.GenPaths, kr *crypto.Keyring) error {
	if err := validateStructure(gen); err != nil {
		return err
	}
	if _, err := InspectDeletedArchive(gen); err != nil {
		return err
	}
	manifest, err := ReadManifest(gen)
	if err != nil {
		return err
	}
	if !manifest.Complete {
		return fmt.Errorf("generation %s manifest is not complete", gen.GenerationID())
	}
	seal, err := ReadSeal(gen, kr)
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

// ValidateAnchoredSealed validates a retained generation whose exact seal is
// pinned by the root. Unlike ValidateSealed, term-bearing entries may name
// resident retired terms because the pre-retirement anchor, not that term's
// MAC alone, is the historical authority.
func ValidateAnchoredSealed(
	gen storepaths.GenPaths,
	anchor crypto.HistoricalGenerationAnchor,
	kr *crypto.Keyring,
) error {
	if err := validateStructure(gen); err != nil {
		return err
	}
	if _, err := InspectDeletedArchive(gen); err != nil {
		return err
	}
	seal, err := ReadAnchoredSeal(gen, anchor, kr)
	if err != nil {
		return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
	}
	live, err := BuildInventory(gen)
	if err != nil {
		return err
	}
	if !slices.Equal(live, seal.Inventory) {
		return fmt.Errorf("generation %s content does not match its anchored seal", gen.GenerationID())
	}
	return nil
}

// VerifyBytesAgainstSeal verifies the exact byte buffer a caller will consume
// against one seal inventory entry. Historical consumers must use this form
// rather than validate a path and then read it again.
func VerifyBytesAgainstSeal(seal *Seal, relativePath string, data []byte) error {
	if seal == nil {
		return fmt.Errorf("missing generation seal")
	}
	index := slices.IndexFunc(seal.Inventory, func(e InventoryEntry) bool {
		return e.Path == relativePath
	})
	if index < 0 {
		return fmt.Errorf("path is absent from the seal")
	}
	sum := sha256.Sum256(data)
	entry := seal.Inventory[index]
	if int64(len(data)) != entry.Size || hex.EncodeToString(sum[:]) != entry.SHA256 {
		return fmt.Errorf("size or digest mismatch")
	}
	term, present, err := crypto.InspectTermEnvelope(data)
	if err != nil {
		return fmt.Errorf("inspect term envelope: %w", err)
	}
	if !present {
		term = 0
	}
	if term != entry.Term {
		return fmt.Errorf("term %d does not match seal term %d", term, entry.Term)
	}
	return nil
}

// ReadAnchoredBytes returns the exact member buffer verified against both the
// root anchor and the anchor-authenticated seal entry.
func ReadAnchoredBytes(
	gen storepaths.GenPaths,
	anchor crypto.HistoricalGenerationAnchor,
	relativePath string,
	kr *crypto.Keyring,
) ([]byte, InventoryEntry, error) {
	manifestBytes, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return nil, InventoryEntry{}, err
	}
	sealBytes, _, err := fsutil.ReadRegularFile(gen.SealPath())
	if err != nil {
		return nil, InventoryEntry{}, err
	}
	seal, err := ParseAnchoredSealBytes(gen, anchor, sealBytes, manifestBytes, kr)
	if err != nil {
		return nil, InventoryEntry{}, err
	}
	index := slices.IndexFunc(seal.Inventory, func(entry InventoryEntry) bool {
		return entry.Path == relativePath
	})
	if index < 0 {
		return nil, InventoryEntry{}, fmt.Errorf("path %q is absent from the anchored seal", relativePath)
	}
	data, _, err := fsutil.ReadRegularFile(
		filepath.Join(gen.Dir(), filepath.FromSlash(relativePath)),
	)
	if err != nil {
		return nil, InventoryEntry{}, err
	}
	if err := VerifyBytesAgainstSeal(seal, relativePath, data); err != nil {
		return nil, InventoryEntry{}, fmt.Errorf(
			"%s does not match generation %s's anchored seal: %w",
			relativePath,
			gen.GenerationID(),
			err,
		)
	}
	return data, seal.Inventory[index], nil
}

// OpenAnchoredEnvelope opens one exact historical term envelope only after
// the root anchor, complete seal, and per-member seal entry all match.
func OpenAnchoredEnvelope(
	gen storepaths.GenPaths,
	anchor crypto.HistoricalGenerationAnchor,
	relativePath string,
	ctx crypto.ObjectContext,
	kr *crypto.Keyring,
) ([]byte, error) {
	data, entry, err := ReadAnchoredBytes(gen, anchor, relativePath, kr)
	if err != nil {
		return nil, err
	}
	if entry.Term <= 0 {
		return nil, fmt.Errorf("anchored member %q is not a term envelope", relativePath)
	}
	plaintext, err := kr.OpenHistoricalGenerationEnvelope(data, ctx, entry.Term)
	if err != nil {
		return nil, fmt.Errorf("open anchored member %q: %w", relativePath, err)
	}
	return plaintext, nil
}

// OpenAnchoredEnvelopeBytes opens an already-read member buffer only after
// exact anchor, seal, manifest, and per-member validation. It lets inventory
// and completion scans consume the same member bytes they hash without
// exposing the keyring's low-level historical operation outside genstore.
func OpenAnchoredEnvelopeBytes(
	gen storepaths.GenPaths,
	anchor crypto.HistoricalGenerationAnchor,
	sealBytes, manifestBytes []byte,
	relativePath string,
	memberBytes []byte,
	ctx crypto.ObjectContext,
	kr *crypto.Keyring,
) ([]byte, error) {
	seal, err := ParseAnchoredSealBytes(
		gen,
		anchor,
		sealBytes,
		manifestBytes,
		kr,
	)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(seal.Inventory, func(entry InventoryEntry) bool {
		return entry.Path == relativePath
	})
	if index < 0 {
		return nil, fmt.Errorf(
			"path %q is absent from the anchored seal",
			relativePath,
		)
	}
	if err := VerifyBytesAgainstSeal(seal, relativePath, memberBytes); err != nil {
		return nil, fmt.Errorf(
			"%s does not match generation %s's anchored seal: %w",
			relativePath,
			gen.GenerationID(),
			err,
		)
	}
	entry := seal.Inventory[index]
	if entry.Term <= 0 {
		return nil, fmt.Errorf(
			"anchored member %q is not a term envelope",
			relativePath,
		)
	}
	plaintext, err := kr.OpenHistoricalGenerationEnvelope(
		memberBytes,
		ctx,
		entry.Term,
	)
	if err != nil {
		return nil, fmt.Errorf("open anchored member %q: %w", relativePath, err)
	}
	return plaintext, nil
}

// validateStructure enforces the complete generation authority shape. Every
// leaf namespace and root authority file is mandatory; deleted/ is a closed
// container; leaf namespaces contain only regular files; and no symlink is
// accepted anywhere.
func validateStructure(gen storepaths.GenPaths) error {
	if err := requireRegularDirectory(gen.Dir()); err != nil {
		return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
	}
	if err := validateGenerationAuthorityShape(gen); err != nil {
		return err
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
		case slices.Contains(generationAuthorityFiles, name):
			// Validated unconditionally above.
		case name == "keys" || name == "keytypes" || name == "deleted":
			// Validated unconditionally above.
		case isDurableWriteResidue(name):
			// Crash residue of WriteFileDurable's temp file (a power loss
			// mid-seal orphans one at the generation root). The rename that
			// commits a durable write is atomic, so a .tmp-* never carries
			// state; reconciliation garbage-collects it. Rejecting it here
			// would send a survivable crash into recovery.
		default:
			return fmt.Errorf("generation %s contains unsupported entry %q", gen.GenerationID(), name)
		}
	}
	return nil
}

func validateGenerationAuthorityShape(gen storepaths.GenPaths) error {
	for _, namespace := range generationLeafNamespaces {
		if err := validateNamespaceDir(filepath.Join(gen.Dir(), namespace)); err != nil {
			return fmt.Errorf("generation %s: %w", gen.GenerationID(), err)
		}
	}
	for _, relative := range generationAuthorityFiles {
		if _, _, err := fsutil.ReadRegularFile(filepath.Join(gen.Dir(), relative)); err != nil {
			return fmt.Errorf("generation %s authority file %s: %w", gen.GenerationID(), relative, err)
		}
	}
	entries, err := os.ReadDir(gen.DeletedDir())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "keys" && entry.Name() != "keytypes" {
			return fmt.Errorf(
				"generation %s deleted archive contains unsupported entry %q",
				gen.GenerationID(),
				entry.Name(),
			)
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

// isDurableWriteResidue reports whether name is an orphaned temp file from a
// crashed durable write of a generation-root record.
func isDurableWriteResidue(name string) bool {
	if strings.HasPrefix(name, storepaths.GenerationSealName+".tmp-") ||
		strings.HasPrefix(name, storepaths.GenerationManifestName+".tmp-") {
		return true
	}
	for _, authority := range generationAuthorityFiles {
		if strings.HasPrefix(name, authority+".tmp-") {
			return true
		}
	}
	return false
}

// hasDurableWriteTempSuffix reports whether name ends in the exact temp-file
// shape os.CreateTemp produces for durable writes: ".tmp-" followed by
// digits. Namespace residue GC must anchor on this suffix — a substring
// match on ".tmp-" would delete a legitimate record whose own name merely
// contains it.
func hasDurableWriteTempSuffix(name string) bool {
	idx := strings.LastIndex(name, ".tmp-")
	if idx < 0 {
		return false
	}
	digits := name[idx+len(".tmp-"):]
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
