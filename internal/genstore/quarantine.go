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
)

// quarantineCandidate is non-authoritative metadata used to decide whether a
// complete final generation directory can be safely relocated intact. A
// successful classification says nothing about whether the generation may be
// selected, opened, or adopted.
type quarantineCandidate struct {
	GenerationID         string
	ParentID             string
	ManifestSHA256       string
	LiveInventorySHA256  string
	AtMintInventoryMatch bool
	EntryCount           int
	EncodedBytes         int64
}

// classifyQuarantineCandidate proves only safe, bounded relocation. It does
// not require at-mint inventory equality: a generation orphaned by authentic
// root rollback may have been current and legitimately mutated after mint.
// Envelope terms are inspected for inventory classification but never opened,
// so a term absent from the restored keyring is not a classification failure.
func classifyQuarantineCandidate(gen storepaths.GenPaths) (quarantineCandidate, error) {
	candidate := quarantineCandidate{GenerationID: gen.GenerationID()}
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
