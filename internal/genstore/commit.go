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
	// with no store root. Root absence alone proves nothing — an established
	// store can lose its root, and that condition requires recovery, never a
	// new lineage (docs/ARCH_GENERATIONS.md §recovery).
	// Mint still verifies the store shows no evidence of generational
	// history before honoring this.
	FirstGeneration bool
	// InitialPassphrase is required only for a first mint. It
	// seals the first wrapped keyring into store-root.enc and is never retained.
	InitialPassphrase []byte
	// Operation and OperationID become the manifest's durable operation
	// identity.
	Operation   string
	OperationID string
	// RollbackCapability carries authenticated restore provenance. Mint binds
	// it to the successor's exact at-mint inventory. Recovery-mode repairs and
	// rollback reconstructions leave it nil.
	RollbackCapability *RollbackCapability
	// RollbackSourceGenerationID records a sealed generation whose content
	// is reconstructed into the new generation. It is distinct from Parent,
	// which must still be the outgoing store-root selection.
	RollbackSourceGenerationID string
	CreatedAt                  time.Time
	// Integrity authenticates the outgoing generation seal. It is required
	// whenever Parent is non-empty and unused for a first generation.
	Integrity *crypto.Keyring
	// OutgoingSealAlreadyWritten declares that a maintenance transaction
	// froze and sealed Parent before staging. Mint validates that exact seal
	// before copying and never rewrites it.
	OutgoingSealAlreadyWritten bool
	// ReplacementKeyring and ReplacementPassphrase request a one-record
	// key-authority plus generation cutover (changepass). They are valid only
	// for an atomic successor with a pre-sealed outgoing generation.
	ReplacementKeyring    *crypto.Keyring
	ReplacementPassphrase []byte
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
	// ValidateCandidate runs the caller's complete semantic validation gates
	// against the staged generation and the authority that will select it.
	// It runs after Apply and structural validation, but before the manifest is
	// written or any staged state is published. Generation-owning application
	// workflows must supply this hook; genstore cannot import signer policy,
	// template, credential, or node-role semantics without inverting ownership.
	ValidateCandidate func(staged storepaths.GenPaths) error
	// AfterPublication runs after the complete successor directory and its
	// parent-directory entry are durable, but before the store root changes.
	// It exists for semantic process checkpoints and must not mutate the store.
	AfterPublication func() error
	// AfterRootCommit runs after store-root.enc has selected the successor.
	// It exists for semantic process checkpoints and must not mutate the store.
	AfterRootCommit func() error
}

// Mint stages, applies, validates, and publishes a complete generation, then
// commits it with a durable store-root replacement. The caller holds the
// identity mutation lock for the whole call. Before publication, errors remove
// staging. After publication but before root replacement, errors can leave a
// complete non-authoritative successor for reconciliation to quarantine. A
// crash at any point leaves either the complete old state or the complete new
// state selected — never a mixture.
//
// Commit order (docs/ARCH_GENERATIONS.md §2):
// stage → copy parent → apply → validate → manifest → fsync all →
// publish rename → fsync generations/ → seal outgoing → replace store root.
func Mint(paths storepaths.Paths, req MintRequest) (storepaths.GenPaths, error) {
	if err := storepaths.ValidateGenerationID(req.GenerationID); err != nil {
		return storepaths.GenPaths{}, err
	}
	if req.Operation == "" || req.OperationID == "" {
		return storepaths.GenPaths{}, fmt.Errorf("mint requires a durable operation identity")
	}
	if req.StartEmpty {
		if req.Parent == "" || req.Apply == nil {
			return storepaths.GenPaths{}, fmt.Errorf(
				"empty reconstruction requires a parent and apply function",
			)
		}
	}
	if req.RollbackSourceGenerationID != "" && (req.Parent == "" || req.Apply == nil) {
		return storepaths.GenPaths{}, fmt.Errorf("rollback source requires a parent and apply function")
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
	if req.Integrity == nil {
		return storepaths.GenPaths{}, fmt.Errorf("store-root mint requires an integrity keyring")
	}
	if req.FirstGeneration && len(req.InitialPassphrase) == 0 {
		return storepaths.GenPaths{}, fmt.Errorf("store-root first mint requires an initial passphrase")
	}
	if req.OutgoingSealAlreadyWritten && req.Parent == "" {
		return storepaths.GenPaths{}, fmt.Errorf("pre-sealed outgoing generation requires a parent")
	}
	replacingRoot := req.ReplacementKeyring != nil || len(req.ReplacementPassphrase) != 0
	if replacingRoot && (req.FirstGeneration || !req.OutgoingSealAlreadyWritten || req.ReplacementKeyring == nil || len(req.ReplacementPassphrase) == 0) {
		return storepaths.GenPaths{}, fmt.Errorf("replacement root requires a successor, a pre-sealed outgoing generation, a successor keyring, and a passphrase")
	}
	// The parent must be exactly the generation store-root.enc names: Mint seals
	// req.Parent as "the outgoing generation", so a stale parent — or an
	// empty parent on a store that already has a root — would seal the
	// wrong generation and leave the real outgoing one unsealed, which
	// reconciliation would then classify as an uncommitted attempt and
	// quarantine. A parentless mint is valid only on a store with no root
	// (initialize or rebuild). This also subsumes the
	// self-parent and parent-must-exist checks: the store root's generation
	// directory is verified by the authenticated selection, and a self-parent request
	// would collide with the existing current directory below.
	if req.FirstGeneration {
		if req.Parent != "" {
			return storepaths.GenPaths{}, fmt.Errorf("atomic store-root first mint must be parentless")
		}
		if _, err := os.Lstat(paths.StoreRootPath()); err == nil {
			return storepaths.GenPaths{}, fmt.Errorf("mint: store root already exists")
		} else if !os.IsNotExist(err) {
			return storepaths.GenPaths{}, err
		}
		if err := verifyFirstMintPreconditions(paths); err != nil {
			return storepaths.GenPaths{}, err
		}
	} else {
		if req.Parent == "" {
			return storepaths.GenPaths{}, fmt.Errorf("atomic store-root successor mint requires a parent")
		}
		exact, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
		if err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("mint: %w", err)
		}
		selection, err := crypto.AuthenticateStoreRoot(exact, req.Integrity)
		if err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("mint: authenticate store root: %w", err)
		}
		if selection.CurrentGenerationID != req.Parent {
			return storepaths.GenPaths{}, fmt.Errorf(
				"mint parent %q is not the store-root current generation %s",
				req.Parent,
				selection.CurrentGenerationID,
			)
		}
		if err := requireMintableGenerationStore(paths, req.Integrity); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("mint preflight: %w", err)
		}
	}

	generationsDir := paths.GenerationsDir()
	if req.OutgoingSealAlreadyWritten {
		if err := ValidateSealed(paths.GenerationPaths(req.Parent), req.Integrity); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("validate pre-sealed outgoing generation: %w", err)
		}
	}
	if req.Parent != "" {
		if _, err := InspectDeletedArchive(paths.GenerationPaths(req.Parent)); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("mint preflight: %w", err)
		}
	}
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
		if err := makeGenerationDirectories(staged); err != nil {
			return storepaths.GenPaths{}, err
		}
	}

	if req.Apply != nil {
		if err := req.Apply(staged); err != nil {
			return storepaths.GenPaths{}, err
		}
	}
	if _, err := InspectDeletedArchive(staged); err != nil {
		return storepaths.GenPaths{}, fmt.Errorf("staged generation deleted archive: %w", err)
	}

	// Validate the complete staged namespaces before anything durable
	// refers to them.
	if err := validateStructureAt(stagingDir, req.GenerationID, false); err != nil {
		return storepaths.GenPaths{}, err
	}
	if req.ValidateCandidate != nil {
		if err := req.ValidateCandidate(staged); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("validate staged generation: %w", err)
		}
	}
	inventory, err := BuildInventory(staged)
	if err != nil {
		return storepaths.GenPaths{}, err
	}
	rollbackCapability, err := bindRollbackCapability(req.RollbackCapability, inventory)
	if err != nil {
		return storepaths.GenPaths{}, err
	}
	if err := WriteManifest(staged, Manifest{
		GenerationID:       req.GenerationID,
		ParentID:           req.Parent,
		CreatedAtUnix:      req.CreatedAt.Unix(),
		Operation:          req.Operation,
		OperationID:        req.OperationID,
		RollbackCapability: rollbackCapability,
		Inventory:          inventory,
		Complete:           true,
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
	// Mandatory: without this a crash can persist the store-root replacement while
	// losing the generation's directory entry.
	if err := fsutil.SyncDir(generationsDir); err != nil {
		return storepaths.GenPaths{}, err
	}
	if req.AfterPublication != nil {
		if err := req.AfterPublication(); err != nil {
			return storepaths.GenPaths{}, err
		}
	}

	// Seal the outgoing generation while it is still current: the last
	// write it ever receives, and what makes it a valid rollback target.
	if req.Parent != "" && !req.OutgoingSealAlreadyWritten {
		if err := WriteSeal(paths.GenerationPaths(req.Parent), req.CreatedAt.Unix(), req.Integrity); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("seal outgoing generation: %w", err)
		}
	}

	var commitErr error
	if replacingRoot {
		commitErr = CommitReplacementStoreRoot(
			paths,
			req.Integrity,
			req.Parent,
			req.ReplacementKeyring,
			req.ReplacementPassphrase,
			req.GenerationID,
		)
	} else {
		if req.FirstGeneration {
			commitErr = CommitInitialStoreRoot(
				paths,
				req.Integrity,
				req.InitialPassphrase,
				req.GenerationID,
			)
		} else {
			commitErr = CommitStoreRoot(
				paths,
				req.Integrity,
				req.Parent,
				req.GenerationID,
			)
		}
	}
	if commitErr != nil {
		return storepaths.GenPaths{}, commitErr
	}
	if req.AfterRootCommit != nil {
		if err := req.AfterRootCommit(); err != nil {
			return storepaths.GenPaths{}, err
		}
	}
	return paths.GenerationPaths(req.GenerationID), nil
}

func bindRollbackCapability(seed *RollbackCapability, inventory []InventoryEntry) (*RollbackCapability, error) {
	if seed == nil {
		return nil, nil
	}
	if seed.OriginOperationID == "" || seed.ArchiveSHA256 == "" || seed.SourceGenerationID == "" || !seed.CleanAtCutover {
		return nil, fmt.Errorf("rollback capability provenance is incomplete")
	}
	digest, err := CanonicalInventoryDigest(inventory)
	if err != nil {
		return nil, err
	}
	bound := *seed
	bound.EntryCount = int64(len(inventory))
	bound.InventorySHA256 = digest
	if err := validateRollbackCapability(&bound); err != nil {
		return nil, err
	}
	return &bound, nil
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
	if err := makeGenerationDirectories(to); err != nil {
		return err
	}
	for _, namespace := range generationLeafNamespaces {
		srcDir := filepath.Join(from.Dir(), namespace)
		dstDir := filepath.Join(to.Dir(), namespace)
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
	for _, relative := range generationAuthorityFiles {
		data, mode, err := fsutil.ReadRegularFile(filepath.Join(from.Dir(), relative))
		if err != nil {
			return fmt.Errorf("copy generation authority file %s: %w", relative, err)
		}
		targetMode := mode.Perm() & fsutil.StoreFilePerm
		dst := filepath.Join(to.Dir(), relative)
		if err := os.WriteFile(dst, data, targetMode); err != nil {
			return err
		}
		if err := os.Chmod(dst, targetMode); err != nil {
			return err
		}
	}
	return nil
}

func makeGenerationDirectories(gen storepaths.GenPaths) error {
	for _, dir := range []string{
		gen.KeysDir(),
		gen.KeyTypeRecordsDir(),
		gen.DeletedDir(),
		gen.DeletedKeysDir(),
		gen.DeletedKeyTypeRecordsDir(),
	} {
		if err := makeNamespaceDir(dir); err != nil {
			return err
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
	gen := storepaths.StagedGenerationPaths(generationID, dir)
	if err := validateGenerationAuthorityShape(gen); err != nil {
		return err
	}
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
		case "keys", "keytypes", "deleted":
			// Validated unconditionally above.
		case "policy.yaml", "policy.yaml.hmac", "node.yaml.hmac":
			// Validated unconditionally above.
		default:
			return fmt.Errorf("generation %s contains unsupported entry %q", generationID, name)
		}
	}
	if requireManifest && !sawManifest {
		return fmt.Errorf("generation %s has no manifest", generationID)
	}
	return nil
}
