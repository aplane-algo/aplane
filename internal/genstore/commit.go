// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// NewGenerationID mints a sortable generation identifier.
func NewGenerationID(now time.Time) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("mint generation ID: %w", err)
	}
	id := fmt.Sprintf("gen-%d-%s", now.Unix(), hex.EncodeToString(suffix))
	if err := storepaths.ValidateGenerationID(id); err != nil {
		return "", err
	}
	return id, nil
}

// MintRequest describes one generation-minting transaction.
type MintRequest struct {
	GenerationID string
	// Parent is the generation being superseded; empty for a store's first
	// generation (migration or initialization).
	Parent string
	// FirstGeneration explicitly authorizes a parentless mint on a store
	// with no CURRENT pointer. Pointer absence alone proves nothing — an
	// established store can lose its pointer, and that condition requires
	// recovery, never a new lineage (docs/ARCH_GENERATIONS.md §recovery).
	// Mint still verifies the store shows no evidence of generational
	// history before honoring this.
	FirstGeneration bool
	// Operation and OperationID become the manifest's durable operation
	// identity.
	Operation   string
	OperationID string
	// RestoreArchiveSHA256 and RestoreRollbackEligible are direct-restore
	// provenance. Recovery-mode repairs are never rollback-eligible.
	RestoreArchiveSHA256    string
	RestoreRollbackEligible bool
	// RollbackSourceGenerationID records a sealed generation whose content
	// is reconstructed into the new generation. It is distinct from Parent,
	// which must still be the outgoing CURRENT generation.
	RollbackSourceGenerationID string
	CreatedAt                  time.Time
	// Integrity authenticates the outgoing generation seal. It is required
	// whenever Parent is non-empty and unused for a first generation.
	Integrity *crypto.Keyring
	// StartEmpty creates empty generation namespaces instead of copying the
	// parent. It is used when Apply reconstructs an authenticated historical
	// source into current-term envelopes; copying the mutable parent first
	// would risk carrying unrelated files into the rollback result.
	StartEmpty bool
	// Apply performs the transaction's changes inside the staged
	// generation. The staged namespaces already contain independent copies
	// of the parent's content, or are empty for a first generation or an
	// authenticated StartEmpty reconstruction.
	Apply func(staged storepaths.GenPaths) error
}

// Mint stages, applies, validates, and publishes a complete generation, then
// commits it with a durable CURRENT flip. The caller holds the identity
// mutation lock for the whole call. On any error the staging directory is
// removed and CURRENT is untouched: the old generation remains
// authoritative, and a crash at any point leaves either the complete old
// state or the complete new state selected — never a mixture.
//
// Commit order (docs/ARCH_GENERATIONS.md §2):
// stage → copy parent → apply → validate → manifest → fsync all →
// publish rename → fsync generations/ → seal outgoing → flip CURRENT.
func Mint(paths storepaths.Paths, req MintRequest) (storepaths.GenPaths, error) {
	if err := storepaths.ValidateGenerationID(req.GenerationID); err != nil {
		return storepaths.GenPaths{}, err
	}
	if req.Operation == "" || req.OperationID == "" {
		return storepaths.GenPaths{}, fmt.Errorf("mint requires a durable operation identity")
	}
	if req.StartEmpty {
		if req.Parent == "" || req.RollbackSourceGenerationID == "" || req.Apply == nil {
			return storepaths.GenPaths{}, fmt.Errorf(
				"empty reconstruction requires a parent, rollback source, and apply function",
			)
		}
	} else if req.RollbackSourceGenerationID != "" {
		return storepaths.GenPaths{}, fmt.Errorf(
			"rollback source requires an empty authenticated reconstruction",
		)
	}
	if req.RollbackSourceGenerationID == req.Parent &&
		req.RollbackSourceGenerationID != "" {
		return storepaths.GenPaths{}, fmt.Errorf(
			"rollback source must differ from the outgoing parent",
		)
	}
	if req.Parent != "" && req.Integrity == nil {
		return storepaths.GenPaths{}, fmt.Errorf("mint with a parent requires an integrity keyring")
	}
	// The parent must be exactly the generation CURRENT names: Mint seals
	// req.Parent as "the outgoing generation", so a stale parent — or an
	// empty parent on a store that already has a CURRENT — would seal the
	// wrong generation and leave the real outgoing one unsealed, which
	// reconciliation would then classify as an uncommitted attempt and
	// delete. A parentless mint is valid only on a store with no CURRENT
	// (initialize, rebuild, first migration). This also subsumes the
	// self-parent and parent-must-exist checks: CURRENT's generation
	// directory is verified by ReadCurrent, and a self-parent request
	// would collide with the existing current directory below.
	if _, err := os.Lstat(paths.CurrentPointerPath()); err != nil {
		if !os.IsNotExist(err) {
			return storepaths.GenPaths{}, err
		}
		if !req.FirstGeneration {
			return storepaths.GenPaths{}, fmt.Errorf("mint: store has no CURRENT pointer; a lost pointer on an established store requires recovery, and a first mint must be explicitly authorized")
		}
		if req.Parent != "" {
			return storepaths.GenPaths{}, fmt.Errorf("mint parent %s: store has no current generation; the first mint must be parentless", req.Parent)
		}
		if err := verifyFirstMintPreconditions(paths); err != nil {
			return storepaths.GenPaths{}, err
		}
	} else {
		if req.FirstGeneration {
			return storepaths.GenPaths{}, fmt.Errorf("mint: store already has a current generation; a first mint is not applicable")
		}
		current, err := ReadCurrent(paths)
		if err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("mint: %w", err)
		}
		if req.Parent != current {
			return storepaths.GenPaths{}, fmt.Errorf("mint parent %q is not the current generation %s", req.Parent, current)
		}
	}

	generationsDir := paths.GenerationsDir()
	if err := fsutil.MkdirAllPrivate(generationsDir); err != nil {
		return storepaths.GenPaths{}, err
	}
	finalDir := paths.GenerationDir(req.GenerationID)
	if _, err := os.Lstat(finalDir); err == nil {
		return storepaths.GenPaths{}, fmt.Errorf("generation %s already exists", req.GenerationID)
	} else if !os.IsNotExist(err) {
		return storepaths.GenPaths{}, err
	}

	stagingDir := filepath.Join(generationsDir, storepaths.GenerationStagingPrefix+req.GenerationID)
	if err := os.Mkdir(stagingDir, fsutil.StoreDirPerm); err != nil {
		return storepaths.GenPaths{}, fmt.Errorf("create generation staging: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stagingDir)
		}
	}()
	if err := os.Chmod(stagingDir, fsutil.StoreDirPerm); err != nil {
		return storepaths.GenPaths{}, err
	}

	// GenPaths bound to the staging directory: same shape, unpublished root.
	staged := stagedGenPaths(paths, req.GenerationID, stagingDir)

	// Independent copies of the parent's live content — never hardlinks: a
	// later in-place write must be unable to reach an inode a prior
	// generation shares.
	if req.Parent != "" && !req.StartEmpty {
		parent := paths.GenerationPaths(req.Parent)
		if err := copyNamespaces(parent, staged); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("copy parent generation: %w", err)
		}
	} else {
		for _, namespace := range generationNamespaces {
			if err := makeNamespaceDir(filepath.Join(stagingDir, namespace)); err != nil {
				return storepaths.GenPaths{}, err
			}
		}
	}

	if req.Apply != nil {
		if err := req.Apply(staged); err != nil {
			return storepaths.GenPaths{}, err
		}
	}

	// Validate the complete staged namespaces before anything durable
	// refers to them.
	if err := validateStructureAt(stagingDir, req.GenerationID, false); err != nil {
		return storepaths.GenPaths{}, err
	}
	inventory, err := BuildInventory(staged)
	if err != nil {
		return storepaths.GenPaths{}, err
	}
	if err := WriteManifest(staged, Manifest{
		GenerationID:               req.GenerationID,
		ParentID:                   req.Parent,
		CreatedAtUnix:              req.CreatedAt.Unix(),
		Operation:                  req.Operation,
		OperationID:                req.OperationID,
		RestoreArchiveSHA256:       req.RestoreArchiveSHA256,
		RestoreRollbackEligible:    req.RestoreRollbackEligible,
		RollbackSourceGenerationID: req.RollbackSourceGenerationID,
		Inventory:                  inventory,
		Complete:                   true,
	}); err != nil {
		return storepaths.GenPaths{}, err
	}

	// fsync every staged file and directory bottom-up, then publish.
	if err := syncTreeBottomUp(stagingDir); err != nil {
		return storepaths.GenPaths{}, err
	}
	if err := os.Rename(stagingDir, finalDir); err != nil {
		return storepaths.GenPaths{}, fmt.Errorf("publish generation: %w", err)
	}
	cleanup = false
	// Mandatory: without this a crash can persist the CURRENT flip while
	// losing the generation's directory entry.
	if err := fsutil.SyncDir(generationsDir); err != nil {
		return storepaths.GenPaths{}, err
	}

	// Seal the outgoing generation while it is still current: the last
	// write it ever receives, and what makes it a valid rollback target.
	if req.Parent != "" {
		if err := WriteSeal(paths.GenerationPaths(req.Parent), req.CreatedAt.Unix(), req.Integrity); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("seal outgoing generation: %w", err)
		}
	}

	if err := WriteCurrent(paths, req.GenerationID); err != nil {
		return storepaths.GenPaths{}, err
	}
	return paths.GenerationPaths(req.GenerationID), nil
}

// RollbackTo repoints CURRENT at a previous sealed generation after
// validating it, sealing the outgoing generation first: a rollback is a
// pointer flip like any other. The caller holds the identity mutation lock.
func RollbackTo(paths storepaths.Paths, targetID string, now time.Time, kr *crypto.Keyring) error {
	current, err := ReadCurrent(paths)
	if err != nil {
		return err
	}
	if current == targetID {
		// Succeeding here would report a rollback that never moved CURRENT.
		// No legitimate caller asks to roll back to the generation that is
		// already current; a self-parent manifest could (and is rejected by
		// manifest validation for the same reason).
		return fmt.Errorf("rollback target %s is already the current generation", targetID)
	}
	target := paths.GenerationPaths(targetID)
	if err := ValidateSealed(target, kr); err != nil {
		return fmt.Errorf("rollback target: %w", err)
	}
	if err := WriteSeal(paths.GenerationPaths(current), now.Unix(), kr); err != nil {
		return fmt.Errorf("seal outgoing generation: %w", err)
	}
	return WriteCurrent(paths, targetID)
}

// verifyFirstMintPreconditions rejects an authorized first mint on any store
// showing evidence of generational history: pointer absence proves nothing
// (docs/ARCH_GENERATIONS.md §recovery), so the generations directory must
// hold no generation at all. The only tolerated residue is staging
// directories from a crashed earlier mint — atomic-rename leftovers that
// reconciliation treats as unconditional garbage.
func verifyFirstMintPreconditions(paths storepaths.Paths) error {
	entries, err := os.ReadDir(paths.GenerationsDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), storepaths.GenerationStagingPrefix) {
			continue
		}
		return fmt.Errorf("first mint: %q exists in the generations directory; this store has generational history and requires recovery, not a new lineage", entry.Name())
	}
	return nil
}

// stagedGenPaths builds a GenPaths whose root is the staging directory. It
// reuses the public constructor's shape by construction: staging and final
// directories have identical internal layout.
func stagedGenPaths(paths storepaths.Paths, generationID, stagingDir string) storepaths.GenPaths {
	return storepaths.StagedGenerationPaths(generationID, stagingDir)
}

func copyNamespaces(from, to storepaths.GenPaths) error {
	for _, namespace := range generationNamespaces {
		srcDir := filepath.Join(from.Dir(), namespace)
		dstDir := filepath.Join(to.Dir(), namespace)
		if err := makeNamespaceDir(dstDir); err != nil {
			return err
		}
		info, err := os.Lstat(srcDir)
		if err != nil {
			// A parent namespace that is missing is damage, never a valid
			// state (validateStructure: absence is damage). Tolerating it
			// here would silently mint a child with an empty namespace —
			// keys vanishing from active state under a clean commit record.
			return fmt.Errorf("parent generation namespace %s: %w", namespace, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("generation namespace is not a regular directory: %s", srcDir)
		}
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			data, mode, err := fsutil.ReadRegularFile(filepath.Join(srcDir, entry.Name()))
			if err != nil {
				return fmt.Errorf("copy %s/%s: %w", namespace, entry.Name(), err)
			}
			dst := filepath.Join(dstDir, entry.Name())
			targetMode := mode.Perm() & fsutil.StoreFilePerm
			if err := os.WriteFile(dst, data, targetMode); err != nil {
				return err
			}
			// Creation modes are umask-masked; restore the clamped private
			// mode without carrying legacy group access forward.
			if err := os.Chmod(dst, targetMode); err != nil {
				return err
			}
		}
	}
	return nil
}

// makeNamespaceDir creates a generation namespace directory with the store
// directory mode. os.Mkdir permissions are umask-masked, so an explicit
// chmod restores the private store mode regardless of the invoking
// process's umask.
func makeNamespaceDir(dir string) error {
	if err := os.Mkdir(dir, fsutil.StoreDirPerm); err != nil {
		return err
	}
	return os.Chmod(dir, fsutil.StoreDirPerm)
}

// syncTreeBottomUp fsyncs every regular file, then every directory from the
// deepest up to root.
func syncTreeBottomUp(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("staged entry is not a regular file: %s", path)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := fsutil.SyncDir(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

// validateStructureAt runs the structural validator against an unpublished
// root (staging) or a published generation directory.
func validateStructureAt(dir, generationID string, requireManifest bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sawManifest := false
	for _, entry := range entries {
		switch name := entry.Name(); name {
		case storepaths.GenerationManifestName:
			sawManifest = true
		case storepaths.GenerationSealName:
			if !requireManifest {
				// Staged generations are pre-publish by definition; a seal
				// there means something wrote the final content record
				// before the generation ever became current. Never accept.
				return fmt.Errorf("staged generation %s carries a seal", generationID)
			}
		case "keys", "keytypes":
			if err := validateNamespaceDir(filepath.Join(dir, name)); err != nil {
				return fmt.Errorf("generation %s: %w", generationID, err)
			}
		default:
			return fmt.Errorf("generation %s contains unsupported entry %q", generationID, name)
		}
	}
	if requireManifest && !sawManifest {
		return fmt.Errorf("generation %s has no manifest", generationID)
	}
	return nil
}
