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

// The quarantine candidate limits are the one size rule for a generation
// directory that quarantine may hold. measureGenerationTree counts every path
// below the directory (the manifest, the authority files, the namespace
// directories and their members, and any durable-write residue) and every
// regular file's bytes. Classification applies the rule before it reads
// anything, quarantine accounting applies it to each quarantined generation,
// and Mint applies it to the staged tree before publishing, so a publication
// a crashed mint leaves behind can always be classified, and a generation
// quarantine accepts can always be read back.
//
// Mint enforces the limits, so they sit above the store's documented count
// caps: the entry limit covers 8,192 cosigner credentials with their public
// sidecars, 8,192 per-key policy documents with their sidecars and a full
// deleted archive together, and the byte limit leaves as much again as a full
// deleted archive for live state. They do not cover every store: signer
// account keys have no cap of their own, and key generation and import grow
// the selected generation in place without this check. A store past the
// limits keeps signing, but no new generation can be committed from it
// (RequireSuccessorFits says why); docs/ARCH_STORE.md gives the supported
// store size, which stays well inside them.
//
// The quarantine total is derived from the candidate byte limit, not set on
// its own: requireMintableGenerationStore refuses a mint unless quarantine has
// room for one more maximum-sized candidate, so a total below the candidate
// limit would refuse every mint. At twice the candidate limit (1 GiB today)
// quarantine holds one maximum-sized candidate and still leaves the next
// mint its reserve.
const (
	quarantineCandidateMaxEntries   = 65_536
	quarantineCandidateMaxFileBytes = 64 << 20
	quarantineCandidateMaxBytes     = 2 * DeletedArchiveMaxEncodedBytes
	quarantineMaxGenerations        = 8
	quarantineMaxBytes              = 2 * quarantineCandidateMaxBytes
	quarantineMaxPruneSelection     = 64
)

// treeLimits bounds one generation directory tree.
type treeLimits struct {
	Entries   int
	FileBytes int64
	Bytes     int64
}

// quarantineCandidateLimits is the rule every caller applies. It is a
// variable only so tests can reach the boundary without writing tens of
// thousands of files; production code never assigns it.
var quarantineCandidateLimits = treeLimits{
	Entries:   quarantineCandidateMaxEntries,
	FileBytes: quarantineCandidateMaxFileBytes,
	Bytes:     quarantineCandidateMaxBytes,
}

// treeUsage is what measureGenerationTree counted.
type treeUsage struct {
	Entries int
	Bytes   int64
}

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
	// EntryCount and EncodedBytes are the generation tree's measure under the
	// quarantine candidate limits: every file and directory below the
	// generation directory, and every regular file's bytes.
	EntryCount   int   `json:"entry_count"`
	EncodedBytes int64 `json:"encoded_bytes"`
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

// DiscardAbandoned irreversibly removes explicitly selected, non-current,
// unsealed final generation directories that reconciliation could not safely
// quarantine. The caller must hold the mutation lock and enforce the distinct
// abandoned-discard authorization, confirmation, and durable-audit contract.
// It applies no size limit and refuses nothing inside the target: it exists
// for the generations that broke the quarantine limits or layout, and it only
// renames and removes.
func DiscardAbandoned(
	paths storepaths.Paths,
	generationIDs []string,
	kr *crypto.Keyring,
) ([]QuarantinePruneResult, error) {
	if len(generationIDs) == 0 || len(generationIDs) > quarantineMaxPruneSelection {
		return nil, fmt.Errorf("abandoned discard requires 1..%d generation IDs", quarantineMaxPruneSelection)
	}
	selected, err := AuthenticateStoreRootSelection(paths, kr)
	if err != nil {
		return nil, err
	}
	current := selected.GenerationID()
	manifest, err := ReadManifest(selected)
	if err != nil {
		return nil, fmt.Errorf("read current generation before abandoned discard: %w", err)
	}
	seen := make(map[string]bool, len(generationIDs))
	results := make([]QuarantinePruneResult, 0, len(generationIDs))
	for _, generationID := range generationIDs {
		if err := storepaths.ValidateGenerationID(generationID); err != nil {
			return results, err
		}
		if seen[generationID] {
			return results, fmt.Errorf("duplicate abandoned generation ID %s", generationID)
		}
		seen[generationID] = true
		if generationID == current || generationID == manifest.ParentID {
			return results, fmt.Errorf("generation %s is authoritative or retained rollback state", generationID)
		}
		path := paths.GenerationDir(generationID)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			results = append(results, QuarantinePruneResult{GenerationID: generationID, AlreadyAbsent: true})
			continue
		}
		if err != nil {
			return results, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return results, fmt.Errorf("abandoned target is not a regular directory: %s", path)
		}
		sealed, err := HasSeal(paths.GenerationPaths(generationID))
		if err != nil {
			return results, err
		}
		if sealed {
			return results, fmt.Errorf("generation %s is sealed retained state, refusing abandoned discard", generationID)
		}
		size, err := removalBytes(path)
		if err != nil {
			return results, err
		}
		tombstone := filepath.Join(paths.GenerationsDir(), storepaths.GenerationStagingPrefix+"discard-"+generationID)
		if err := os.Rename(path, tombstone); err != nil {
			return results, fmt.Errorf("publish abandoned discard tombstone %s: %w", generationID, err)
		}
		if err := fsutil.SyncDir(paths.GenerationsDir()); err != nil {
			return results, err
		}
		if err := os.RemoveAll(tombstone); err != nil {
			return results, fmt.Errorf("discard abandoned generation %s: %w", generationID, err)
		}
		if err := fsutil.SyncDir(paths.GenerationsDir()); err != nil {
			return results, err
		}
		results = append(results, QuarantinePruneResult{GenerationID: generationID, EncodedBytes: size})
	}
	return results, nil
}

// ListQuarantined returns deterministic non-authoritative metadata for the
// currently quarantined generation publications. It never returns GenPaths or
// otherwise makes the namespace addressable by signing and history APIs. A
// non-nil kr additionally classifies envelope terms under the currently
// authenticated authority without opening or returning plaintext.
func ListQuarantined(paths storepaths.Paths, kr *crypto.Keyring) ([]QuarantineRecord, error) {
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
// Like DiscardAbandoned it applies no size limit, so it can remove a
// quarantine entry that the candidate limits would refuse.
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
		tombstone := filepath.Join(
			paths.QuarantineDir(), storepaths.GenerationStagingPrefix+"prune-"+generationID,
		)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			if err := finishInterruptedPrune(paths, tombstone, generationID); err != nil {
				return results, err
			}
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
		size, err := removalBytes(path)
		if err != nil {
			return results, err
		}
		result.EncodedBytes = size
		if _, err := os.Lstat(tombstone); err == nil {
			return results, fmt.Errorf("quarantine prune tombstone already exists: %s", tombstone)
		} else if !os.IsNotExist(err) {
			return results, err
		}
		if err := os.Rename(path, tombstone); err != nil {
			return results, fmt.Errorf("publish quarantine prune tombstone %s: %w", generationID, err)
		}
		if err := fsutil.SyncDir(paths.QuarantinedGenerationsDir()); err != nil {
			return results, fmt.Errorf("confirm quarantine prune source %s: %w", generationID, err)
		}
		if err := fsutil.SyncDir(paths.QuarantineDir()); err != nil {
			return results, fmt.Errorf("confirm quarantine prune tombstone %s: %w", generationID, err)
		}
		if err := os.RemoveAll(tombstone); err != nil {
			return results, fmt.Errorf("prune quarantined generation %s: %w", generationID, err)
		}
		if err := fsutil.SyncDir(paths.QuarantineDir()); err != nil {
			return results, fmt.Errorf("confirm quarantine prune %s: %w", generationID, err)
		}
		results = append(results, result)
	}
	return results, nil
}

// finishInterruptedPrune removes the tombstone an interrupted prune of the
// generation left behind, if there is one, and makes its removal durable.
func finishInterruptedPrune(paths storepaths.Paths, tombstone, generationID string) error {
	tombstoneInfo, tombstoneErr := os.Lstat(tombstone)
	if os.IsNotExist(tombstoneErr) {
		return nil
	}
	if tombstoneErr != nil {
		return tombstoneErr
	}
	if tombstoneInfo.Mode()&os.ModeSymlink != 0 || !tombstoneInfo.IsDir() {
		return fmt.Errorf("quarantine prune tombstone is not a regular directory: %s", tombstone)
	}
	if err := os.RemoveAll(tombstone); err != nil {
		return fmt.Errorf("finish quarantine prune %s: %w", generationID, err)
	}
	return fsutil.SyncDir(paths.QuarantineDir())
}

// classifyQuarantineCandidate proves only safe, bounded relocation. It does
// not require at-mint inventory equality: a generation orphaned by authentic
// root rollback may have been current and legitimately mutated after mint.
// Envelope terms are inspected for inventory classification but never opened,
// so a term absent from the restored keyring is not a classification failure.
func classifyQuarantineCandidate(gen storepaths.GenPaths, kr *crypto.Keyring) (QuarantineRecord, error) {
	candidate := QuarantineRecord{GenerationID: gen.GenerationID()}
	// Size the whole tree before reading any of it.
	usage, err := measureGenerationTree(gen.Dir(), quarantineCandidateLimits)
	if err != nil {
		return candidate, fmt.Errorf("classify abandoned generation %s: %w", gen.GenerationID(), err)
	}
	if err := validateStructure(gen); err != nil {
		return candidate, fmt.Errorf("classify abandoned generation: %w", err)
	}

	manifestBytes, _, err := fsutil.ReadRegularFileLimited(
		gen.ManifestPath(),
		quarantineCandidateLimits.FileBytes,
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
	candidate.EntryCount = usage.Entries
	candidate.EncodedBytes = usage.Bytes

	live, validation, err := buildBoundedQuarantineInventory(gen, kr)
	if err != nil {
		return candidate, err
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

// requireMintableGenerationStore reserves enough quarantine capacity for the
// largest publication this mint can leave abandoned and refuses to mint while
// reconciliation residue is pending. Keeping this in genstore prevents
// changepass, credential restore, rollback, and future mint callers from
// drifting on the capacity invariant.
func requireMintableGenerationStore(paths storepaths.Paths, kr *crypto.Keyring) error {
	report, err := InspectStoreRoot(paths, kr)
	if err != nil {
		return err
	}
	if len(report.DiscardedStaging) > 0 || len(report.Quarantined) > 0 || report.RetainedUnsealedParent != "" {
		return fmt.Errorf("generation store requires reconciliation before another mint")
	}
	count, encodedBytes, err := quarantineUsage(paths)
	if err != nil {
		return fmt.Errorf("inspect quarantine capacity: %w", err)
	}
	if count >= quarantineMaxGenerations || encodedBytes > quarantineMaxBytes-quarantineCandidateLimits.Bytes {
		return fmt.Errorf(
			"generation quarantine lacks the reserved capacity required for a mint; prune quarantine first",
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
		usage, err := measureGenerationTree(paths.QuarantinedGenerationDir(entry.Name()), quarantineCandidateLimits)
		if err != nil {
			return 0, 0, fmt.Errorf("quarantined generation %s: %w", entry.Name(), err)
		}
		if usage.Bytes > quarantineMaxBytes-total {
			return 0, 0, fmt.Errorf("quarantine exceeds byte limit %d", quarantineMaxBytes)
		}
		total += usage.Bytes
	}
	return len(entries), total, nil
}

// RequireSuccessorFits refuses, before anything is staged, a mint from parent
// whose successor would break the quarantine candidate limits. Ordinary key
// changes grow the selected generation in place without minting, so it can
// pass the limits between mints. A successor carries everything parent holds
// except its seal and its manifest, and writes a manifest of its own, so
// parent measured that way is a lower bound on the staged tree of a mint that
// adds nothing. Mint's check of the staged tree stays the authority; this
// spares an over-limit store a full copy, re-encryption and validation on
// every attempt, and says what to do.
func RequireSuccessorFits(parent storepaths.GenPaths) error {
	_, err := measureTree(parent.Dir(), quarantineCandidateLimits, func(path string) treeCount {
		switch path {
		case parent.SealPath():
			return countNothing
		case parent.ManifestPath():
			return countEntryOnly
		default:
			return countPath
		}
	})
	if err != nil {
		return fmt.Errorf(
			"generation %s holds more than one generation may (%w); no new generation can be committed until it is back under the limit: delete keys and prune them from the deleted archive, or prune the deleted archive",
			parent.GenerationID(), err,
		)
	}
	return nil
}

// treeCount says what measureTree counts for one path.
type treeCount int

const (
	countPath      treeCount = iota // the entry and, for a file, its bytes
	countEntryOnly                  // the entry, not its bytes
	countNothing                    // nothing
)

// measureGenerationTree counts every path below root and every regular file's
// bytes, and refuses a tree that breaks limits, holds a symlink or an
// irregular file, or is not itself a directory. It reads no file contents and
// follows no link.
func measureGenerationTree(root string, limits treeLimits) (treeUsage, error) {
	return measureTree(root, limits, nil)
}

// measureTree is measureGenerationTree with count deciding, path by path,
// what is counted; nil counts every path.
func measureTree(root string, limits treeLimits, count func(path string) treeCount) (treeUsage, error) {
	var usage treeUsage
	info, err := os.Lstat(root)
	if err != nil {
		return usage, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return usage, fmt.Errorf("generation is not a regular directory: %s", root)
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rule := countPath
		if count != nil {
			rule = count(path)
		}
		if rule == countNothing {
			return nil
		}
		usage.Entries++
		if usage.Entries > limits.Entries {
			return fmt.Errorf("generation tree exceeds entry limit %d", limits.Entries)
		}
		if rule == countEntryOnly {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generation contains symlink: %s", path)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("generation contains irregular file: %s", path)
		}
		if info.Size() > limits.FileBytes {
			return fmt.Errorf("generation member %s exceeds size limit %d", path, limits.FileBytes)
		}
		if info.Size() > limits.Bytes-usage.Bytes {
			return fmt.Errorf("generation tree exceeds byte limit %d", limits.Bytes)
		}
		usage.Bytes += info.Size()
		return nil
	})
	return usage, err
}

// removalBytes totals the regular-file bytes below root for a removal's
// result. It has no limit and refuses nothing inside the tree, and it follows
// no link.
func removalBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// buildBoundedQuarantineInventory reads a candidate that measureGenerationTree
// has already sized; each read is still bounded by the per-file limit.
func buildBoundedQuarantineInventory(gen storepaths.GenPaths, kr *crypto.Keyring) ([]InventoryEntry, TermValidation, error) {
	var inventory []InventoryEntry
	var validation TermValidation
	addMember := func(relative string) error {
		data, _, err := fsutil.ReadRegularFileLimited(
			filepath.Join(gen.Dir(), filepath.FromSlash(relative)),
			quarantineCandidateLimits.FileBytes,
		)
		if err != nil {
			return fmt.Errorf("classify %s: %w", relative, err)
		}
		sum := sha256.Sum256(data)
		term, present, inspectErr := crypto.InspectTermEnvelope(data)
		ctx, termBearing := quarantineMemberContext(relative)
		switch {
		case inspectErr != nil:
			validation.Failed++
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
		inventory = append(inventory, InventoryEntry{
			Path:   relative,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
			Term:   term,
		})
		return nil
	}
	authority, err := presentAuthorityFiles(gen)
	if err != nil {
		return nil, validation, err
	}
	for _, relative := range authority {
		if err := addMember(relative); err != nil {
			return nil, validation, err
		}
	}
	for _, namespace := range generationLeafNamespaces {
		dir := filepath.Join(gen.Dir(), namespace)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, validation, err
		}
		for _, entry := range entries {
			if err := addMember(filepath.ToSlash(filepath.Join(namespace, entry.Name()))); err != nil {
				return nil, validation, err
			}
		}
	}
	slices.SortFunc(inventory, func(a, b InventoryEntry) int {
		return strings.Compare(a.Path, b.Path)
	})
	return inventory, validation, nil
}

func quarantineMemberContext(relative string) (crypto.ObjectContext, bool) {
	base := filepath.Base(relative)
	switch {
	case strings.HasSuffix(base, ".key"):
		return crypto.AccountKeyContext(strings.TrimSuffix(base, ".key")), true
	case strings.HasSuffix(base, ".cos"):
		return crypto.CosignerCredentialContext(strings.TrimSuffix(base, ".cos")), true
	case strings.HasSuffix(base, ".template"):
		return crypto.KeyTypeTemplateContext(strings.TrimSuffix(base, ".template")), true
	default:
		return crypto.ObjectContext{}, false
	}
}
