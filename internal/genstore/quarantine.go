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
	// TermValidation records best-effort integrity classification. Failures
	// and unavailable terms never grant authority and do not veto safe,
	// bounded relocation.
	TermValidation TermValidation `json:"term_validation"`
}

// TermValidation summarizes envelope checks over a quarantine candidate.
type TermValidation struct {
	Verified        int `json:"verified"`
	TermUnavailable int `json:"term_unavailable"`
	Failed          int `json:"failed"`
}

// QuarantinePruneResult records one explicit quarantine disposition. An
// already-absent target is successful so an interrupted multi-target prune is
// safely retryable with the same request.
type QuarantinePruneResult struct {
	GenerationID  string `json:"generation_id"`
	EncodedBytes  int64  `json:"encoded_bytes"`
	AlreadyAbsent bool   `json:"already_absent,omitempty"`
}

// ListQuarantined returns deterministic non-authoritative metadata for the
// currently quarantined generation publications. It never returns GenPaths or
// otherwise makes the namespace addressable by signing and history APIs.
func ListQuarantined(paths storepaths.Paths) ([]QuarantineRecord, error) {
	return listQuarantined(paths, nil)
}

// ListQuarantinedWithKeyring additionally classifies envelope terms under the
// currently authenticated authority without opening or returning plaintext.
func ListQuarantinedWithKeyring(paths storepaths.Paths, kr *crypto.Keyring) ([]QuarantineRecord, error) {
	return listQuarantined(paths, kr)
}

func listQuarantined(paths storepaths.Paths, kr *crypto.Keyring) ([]QuarantineRecord, error) {
	if _, _, err := quarantineUsage(paths); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(paths.QuarantinedGenerationsDir())
	if os.IsNotExist(err) {
		return []QuarantineRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]QuarantineRecord, 0, len(entries))
	for _, entry := range entries {
		if err := storepaths.ValidateGenerationID(entry.Name()); err != nil {
			return nil, fmt.Errorf("unexpected quarantine entry %q", entry.Name())
		}
		// This internal handle exists only to reuse strict bounded generation
		// parsing. It is rooted at quarantine and is never returned to a caller.
		gen := storepaths.StagedGenerationPaths(
			entry.Name(),
			paths.QuarantinedGenerationDir(entry.Name()),
		)
		record, err := classifyQuarantineCandidate(gen, kr)
		if err != nil {
			return nil, fmt.Errorf("inspect quarantined generation %s: %w", entry.Name(), err)
		}
		records = append(records, record)
	}
	slices.SortFunc(records, func(a, b QuarantineRecord) int {
		return strings.Compare(a.GenerationID, b.GenerationID)
	})
	return records, nil
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
func classifyQuarantineCandidate(gen storepaths.GenPaths, kr *crypto.Keyring) (QuarantineRecord, error) {
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

	live, liveBytes, validation, err := buildBoundedQuarantineInventory(gen, kr)
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
	candidate.TermValidation = validation
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

func buildBoundedQuarantineInventory(gen storepaths.GenPaths, kr *crypto.Keyring) ([]InventoryEntry, int64, TermValidation, error) {
	var inventory []InventoryEntry
	var totalBytes int64
	var validation TermValidation
	addMember := func(relative string) error {
		data, _, err := fsutil.ReadRegularFileLimited(
			filepath.Join(gen.Dir(), filepath.FromSlash(relative)),
			quarantineCandidateMaxFileBytes,
		)
		if err != nil {
			return fmt.Errorf("classify %s: %w", relative, err)
		}
		totalBytes += int64(len(data))
		if totalBytes > quarantineCandidateMaxBytes {
			return fmt.Errorf(
				"generation %s exceeds quarantine byte limit %d",
				gen.GenerationID(),
				quarantineCandidateMaxBytes,
			)
		}
		sum := sha256.Sum256(data)
		term, present, inspectErr := crypto.InspectTermEnvelope(data)
		ctx, termBearing := quarantineMemberContext(relative)
		switch {
		case inspectErr != nil:
			validation.Failed++
			term = 0
		case termBearing && !present:
			validation.Failed++
		case !termBearing && present:
			validation.Failed++
		case termBearing && kr == nil:
			validation.TermUnavailable++
		case termBearing:
			_, available, verifyErr := kr.VerifyKnownTermEnvelope(data, ctx)
			if !available && verifyErr == nil {
				validation.TermUnavailable++
			} else if verifyErr != nil {
				validation.Failed++
			} else {
				validation.Verified++
			}
		}
		if !present || inspectErr != nil {
			term = 0
		}
		inventory = append(inventory, InventoryEntry{
			Path:   relative,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
			Term:   term,
		})
		return nil
	}
	for _, relative := range generationAuthorityFiles {
		if len(inventory)+1 > quarantineCandidateMaxFiles {
			return nil, 0, validation, fmt.Errorf(
				"generation %s exceeds quarantine file limit %d",
				gen.GenerationID(),
				quarantineCandidateMaxFiles,
			)
		}
		if err := addMember(relative); err != nil {
			return nil, 0, validation, err
		}
	}
	for _, namespace := range generationLeafNamespaces {
		dir := filepath.Join(gen.Dir(), namespace)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, 0, validation, err
		}
		if len(inventory)+len(entries) > quarantineCandidateMaxFiles {
			return nil, 0, validation, fmt.Errorf(
				"generation %s exceeds quarantine file limit %d",
				gen.GenerationID(),
				quarantineCandidateMaxFiles,
			)
		}
		for _, entry := range entries {
			if err := addMember(filepath.ToSlash(filepath.Join(namespace, entry.Name()))); err != nil {
				return nil, 0, validation, err
			}
		}
	}
	slices.SortFunc(inventory, func(a, b InventoryEntry) int {
		return strings.Compare(a.Path, b.Path)
	})
	return inventory, totalBytes, validation, nil
}

func quarantineMemberContext(relative string) (crypto.ObjectContext, bool) {
	base := filepath.Base(relative)
	switch {
	case strings.HasSuffix(base, ".key"):
		return crypto.AccountKeyContext(strings.TrimSuffix(base, ".key")), true
	case strings.HasSuffix(base, ".sen"):
		return crypto.SentryCredentialContext(strings.TrimSuffix(base, ".sen")), true
	case strings.HasSuffix(base, ".template"):
		return crypto.KeyTypeTemplateContext(strings.TrimSuffix(base, ".template")), true
	default:
		return crypto.ObjectContext{}, false
	}
}
