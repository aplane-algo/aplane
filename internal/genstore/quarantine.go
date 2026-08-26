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

// These are closed safety bounds for classifying one complete abandoned
// publication. Capacity tests may tighten them before the new layout gate is
// enabled, but production code must never classify through an unbounded read.
const (
	quarantineCandidateMaxFiles     = 4_096
	quarantineCandidateMaxFileBytes = 64 << 20
	quarantineCandidateMaxBytes     = 256 << 20
	quarantineManifestMaxBytes      = 16 << 20
	quarantineMaxGenerations        = 8
	quarantineMaxBytes              = 1 << 30
	quarantineMaxPruneSelection     = 64
)

// QuarantineRecord is non-authoritative metadata used to decide whether a
// complete final generation directory can be safely relocated intact. A
// successful classification says nothing about whether the generation may be
// selected, opened, or adopted.
type QuarantineRecord struct {
	GenerationID         string `json:"generation_id"`
	ParentID             string `json:"parent_id,omitempty"`
	ManifestSHA256       string `json:"manifest_sha256"`
	LiveInventorySHA256  string `json:"live_inventory_sha256"`
	AtMintInventoryMatch bool   `json:"at_mint_inventory_match"`
	EntryCount           int    `json:"entry_count"`
	EncodedBytes         int64  `json:"encoded_bytes"`
}

// QuarantinePruneResult records one explicit quarantine disposition. An
// already-absent target is successful so an interrupted multi-target prune is
// safely retryable with the same request.
type QuarantinePruneResult struct {
	GenerationID  string `json:"generation_id"`
	EncodedBytes  int64  `json:"encoded_bytes"`
	AlreadyAbsent bool   `json:"already_absent,omitempty"`
}

// PruneQuarantined irreversibly removes only explicitly selected
// non-authoritative quarantine directories. The caller must hold the store
// mutation lock and enforce authorization, confirmation, and durable audit.
// Active and retained generation paths are not accepted by construction.
func PruneQuarantined(
	paths storepaths.Paths,
	generationIDs []string,
) ([]QuarantinePruneResult, error) {
	if len(generationIDs) == 0 {
		return nil, fmt.Errorf("quarantine prune requires at least one generation ID")
	}
	if len(generationIDs) > quarantineMaxPruneSelection {
		return nil, fmt.Errorf(
			"quarantine prune selection exceeds limit %d",
			quarantineMaxPruneSelection,
		)
	}
	seen := make(map[string]struct{}, len(generationIDs))
	for _, generationID := range generationIDs {
		if err := storepaths.ValidateGenerationID(generationID); err != nil {
			return nil, err
		}
		if _, duplicate := seen[generationID]; duplicate {
			return nil, fmt.Errorf("duplicate quarantine generation ID %s", generationID)
		}
		seen[generationID] = struct{}{}
	}

	results := make([]QuarantinePruneResult, 0, len(generationIDs))
	for _, generationID := range generationIDs {
		result := QuarantinePruneResult{GenerationID: generationID}
		path := paths.QuarantinedGenerationDir(generationID)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			result.AlreadyAbsent = true
			results = append(results, result)
			continue
		}
		if err != nil {
			return results, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return results, fmt.Errorf("quarantine target is not a regular directory: %s", path)
		}
		size, err := boundedTreeSize(path, quarantineMaxBytes)
		if err != nil {
			return results, err
		}
		result.EncodedBytes = size
		if err := os.RemoveAll(path); err != nil {
			return results, fmt.Errorf("prune quarantined generation %s: %w", generationID, err)
		}
		if err := fsutil.SyncDir(paths.QuarantinedGenerationsDir()); err != nil {
			return results, fmt.Errorf("confirm quarantine prune %s: %w", generationID, err)
		}
		results = append(results, result)
	}
	return results, nil
}

// classifyQuarantineCandidate proves only safe, bounded relocation. It does
// not require at-mint inventory equality: a generation orphaned by authentic
// root rollback may have been current and legitimately mutated after mint.
// Envelope terms are inspected for inventory classification but never opened,
// so a term absent from the restored keyring is not a classification failure.
func classifyQuarantineCandidate(gen storepaths.GenPaths) (QuarantineRecord, error) {
	candidate := QuarantineRecord{GenerationID: gen.GenerationID()}
	if err := validateStructure(gen); err != nil {
		return candidate, fmt.Errorf("classify abandoned generation: %w", err)
	}

	manifestBytes, _, err := fsutil.ReadRegularFileLimited(
		gen.ManifestPath(),
		quarantineManifestMaxBytes,
	)
	if err != nil {
		return candidate, fmt.Errorf("classify abandoned generation manifest: %w", err)
	}
	manifest, err := ParseManifestBytes(gen, manifestBytes)
	if err != nil {
		return candidate, err
	}
	if !manifest.Complete {
		return candidate, fmt.Errorf("generation %s manifest is not complete", gen.GenerationID())
	}
	manifestSum := sha256.Sum256(manifestBytes)
	candidate.ManifestSHA256 = hex.EncodeToString(manifestSum[:])
	candidate.ParentID = manifest.ParentID
	candidate.EntryCount = 1
	candidate.EncodedBytes = int64(len(manifestBytes))

	live, liveBytes, err := buildBoundedQuarantineInventory(gen)
	if err != nil {
		return candidate, err
	}
	candidate.EntryCount += len(live)
	candidate.EncodedBytes += liveBytes
	if candidate.EncodedBytes > quarantineCandidateMaxBytes {
		return candidate, fmt.Errorf(
			"generation %s exceeds quarantine byte limit %d",
			gen.GenerationID(),
			quarantineCandidateMaxBytes,
		)
	}
	digest, err := CanonicalInventoryDigest(live)
	if err != nil {
		return candidate, fmt.Errorf("classify abandoned generation inventory: %w", err)
	}
	candidate.LiveInventorySHA256 = digest
	candidate.AtMintInventoryMatch = slices.Equal(live, manifest.Inventory)
	return candidate, nil
}

func quarantinePublication(paths storepaths.Paths, candidate QuarantineRecord) error {
	count, encodedBytes, err := quarantineUsage(paths)
	if err != nil {
		return err
	}
	if err := checkQuarantineCapacity(count, encodedBytes, candidate); err != nil {
		return err
	}

	destination := paths.QuarantinedGenerationDir(candidate.GenerationID)
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("quarantine destination already exists for %s", candidate.GenerationID)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := fsutil.MkdirAllPrivate(paths.QuarantinedGenerationsDir()); err != nil {
		return fmt.Errorf("create generation quarantine: %w", err)
	}
	// Make the reserved namespace durable before publishing into it.
	for _, dir := range []string{
		paths.ProductDir(),
		paths.QuarantineDir(),
		paths.QuarantinedGenerationsDir(),
	} {
		if err := fsutil.SyncDir(dir); err != nil {
			return fmt.Errorf("sync generation quarantine: %w", err)
		}
	}

	if err := os.Rename(paths.GenerationDir(candidate.GenerationID), destination); err != nil {
		return fmt.Errorf("quarantine generation %s: %w", candidate.GenerationID, err)
	}
	// A cross-directory rename changes both directory entry sets. Both syncs
	// are required before reconciliation may report durable quarantine.
	if err := fsutil.SyncDir(paths.GenerationsDir()); err != nil {
		return fmt.Errorf("confirm quarantine source removal: %w", err)
	}
	if err := fsutil.SyncDir(paths.QuarantinedGenerationsDir()); err != nil {
		return fmt.Errorf("confirm quarantine publication: %w", err)
	}
	return nil
}

func checkQuarantineCapacity(count int, encodedBytes int64, candidate QuarantineRecord) error {
	if count >= quarantineMaxGenerations {
		return fmt.Errorf(
			"quarantine generation limit %d reached; candidate %s preserved in place",
			quarantineMaxGenerations,
			candidate.GenerationID,
		)
	}
	if encodedBytes > quarantineMaxBytes || candidate.EncodedBytes > quarantineMaxBytes-encodedBytes {
		return fmt.Errorf(
			"quarantine byte limit %d reached; candidate %s preserved in place",
			quarantineMaxBytes,
			candidate.GenerationID,
		)
	}
	return nil
}

func quarantineUsage(paths storepaths.Paths) (int, int64, error) {
	dir := paths.QuarantinedGenerationsDir()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	if len(entries) > quarantineMaxGenerations {
		return 0, 0, fmt.Errorf("quarantine exceeds generation limit %d", quarantineMaxGenerations)
	}
	var total int64
	for _, entry := range entries {
		if err := storepaths.ValidateGenerationID(entry.Name()); err != nil {
			return 0, 0, fmt.Errorf("unexpected quarantine entry %q", entry.Name())
		}
		path := paths.QuarantinedGenerationDir(entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return 0, 0, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return 0, 0, fmt.Errorf("quarantine entry is not a regular directory: %s", path)
		}
		size, err := boundedTreeSize(path, quarantineMaxBytes-total)
		if err != nil {
			return 0, 0, err
		}
		total += size
	}
	return len(entries), total, nil
}

func boundedTreeSize(root string, remaining int64) (int64, error) {
	if remaining < 0 {
		return 0, fmt.Errorf("quarantine exceeds byte limit %d", quarantineMaxBytes)
	}
	var total int64
	var entries int
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		entries++
		if entries > quarantineCandidateMaxFiles {
			return fmt.Errorf("quarantine generation exceeds entry limit %d", quarantineCandidateMaxFiles)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("quarantine contains symlink: %s", path)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("quarantine contains irregular file: %s", path)
		}
		if info.Size() > remaining-total {
			return fmt.Errorf("quarantine exceeds byte limit %d", quarantineMaxBytes)
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func buildBoundedQuarantineInventory(gen storepaths.GenPaths) ([]InventoryEntry, int64, error) {
	var inventory []InventoryEntry
	var totalBytes int64
	for _, namespace := range generationNamespaces {
		dir := filepath.Join(gen.Dir(), namespace)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, 0, err
		}
		if len(inventory)+len(entries) > quarantineCandidateMaxFiles {
			return nil, 0, fmt.Errorf(
				"generation %s exceeds quarantine file limit %d",
				gen.GenerationID(),
				quarantineCandidateMaxFiles,
			)
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			data, _, err := fsutil.ReadRegularFileLimited(path, quarantineCandidateMaxFileBytes)
			if err != nil {
				return nil, 0, fmt.Errorf("classify %s/%s: %w", namespace, entry.Name(), err)
			}
			totalBytes += int64(len(data))
			if totalBytes > quarantineCandidateMaxBytes {
				return nil, 0, fmt.Errorf(
					"generation %s exceeds quarantine byte limit %d",
					gen.GenerationID(),
					quarantineCandidateMaxBytes,
				)
			}
			sum := sha256.Sum256(data)
			term, present, err := crypto.InspectTermEnvelope(data)
			if err != nil {
				return nil, 0, fmt.Errorf(
					"classify %s/%s term envelope: %w",
					namespace,
					entry.Name(),
					err,
				)
			}
			if !present {
				term = 0
			}
			inventory = append(inventory, InventoryEntry{
				Path:   namespace + "/" + entry.Name(),
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(data)),
				Term:   term,
			})
		}
	}
	slices.SortFunc(inventory, func(a, b InventoryEntry) int {
		return strings.Compare(a.Path, b.Path)
	})
	return inventory, totalBytes, nil
}
