// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	// new lineage (docs/ARCH_STORE.md, "Recovery and restoration").
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
	CreatedAt          time.Time
	// Integrity authenticates the store root and the outgoing generation's
	// seal. Every mint requires it, a first generation included.
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
	// Apply performs the transaction's changes inside the staged
	// generation. The staged namespaces already contain independent copies
	// of the parent's content, or are empty for a first generation.
	Apply func(staged storepaths.GenPaths) error
	// ValidateCandidate runs the caller's complete semantic validation gates
	// against the staged generation and the authority that will select it.
	// It runs after Apply and structural validation, but before the manifest is
	// written or any staged state is published. Generation-owning application
	// workflows must supply this hook; genstore cannot import signer policy,
	// template, credential, or node-role semantics without inverting ownership.
	// Mint refuses a request without it unless SkipCandidateValidation is set.
	ValidateCandidate func(staged storepaths.GenPaths) error
	// SkipCandidateValidation lets a test helper mint with structural
	// validation only. Production code never sets it (test/arch enforces
	// this).
	SkipCandidateValidation bool
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
// Commit order (docs/ARCH_STORE.md, "Ordinary generation commit"):
// stage → copy parent → apply → validate → manifest → size check → fsync all →
// publish rename → fsync generations/ → seal outgoing → replace store root.
func Mint(paths storepaths.Paths, req MintRequest) (storepaths.GenPaths, error) {
	if err := req.validate(); err != nil {
		return storepaths.GenPaths{}, err
	}
	replacingRoot := req.replacesRoot()
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
		if err := verifyFirstMint(paths, req); err != nil {
			return storepaths.GenPaths{}, err
		}
	} else if err := verifySuccessorMint(paths, req); err != nil {
		return storepaths.GenPaths{}, err
	}

	generationsDir := paths.GenerationsDir()
	if req.OutgoingSealAlreadyWritten {
		if err := ValidateSealed(paths.GenerationPaths(req.Parent), req.Integrity); err != nil {
			return storepaths.GenPaths{}, fmt.Errorf("validate pre-sealed outgoing generation: %w", err)
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
	staged := storepaths.StagedGenerationPaths(req.GenerationID, stagingDir)

	// Independent copies of the parent's live content — never hardlinks: a
	// later in-place write must be unable to reach an inode a prior
	// generation shares.
	if req.Parent != "" {
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
	if err := validateStagedStructure(staged); err != nil {
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
	// A failure between publication and the root replacement leaves this tree
	// for reconciliation to quarantine, and requireMintableGenerationStore
	// reserved room for one quarantine candidate: refuse a tree that would not
	// be one.
	if _, err := measureGenerationTree(stagingDir, quarantineCandidateLimits); err != nil {
		return storepaths.GenPaths{}, fmt.Errorf(
			"staged generation %s does not fit the quarantine candidate limits: %w", req.GenerationID, err,
		)
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
		outcome := NotCommitted
		if RootCommitUncertain(commitErr) {
			outcome = Uncertain
		}
		return storepaths.GenPaths{}, &mintError{outcome: outcome, err: commitErr}
	}
	if req.AfterRootCommit != nil {
		if err := req.AfterRootCommit(); err != nil {
			return storepaths.GenPaths{}, &mintError{outcome: Committed, err: err}
		}
	}
	return paths.GenerationPaths(req.GenerationID), nil
}

// MintOutcome is what a mint left the store root selecting.
type MintOutcome int

const (
	// NotCommitted: the root still selects the parent. Every failure before
	// the root replacement is one, and so is a replacement that failed with
	// the old root proven in place (the root commit returns a plain error
	// only then).
	NotCommitted MintOutcome = iota
	// Committed: the root selects the new generation. With an error, a step
	// after the root replacement failed.
	Committed
	// Uncertain: the root may select either. The replacement's durability
	// could not be confirmed, or its outcome could not be classified
	// (RootCommitUncertain).
	Uncertain
)

func (o MintOutcome) String() string {
	switch o {
	case NotCommitted:
		return "not committed"
	case Committed:
		return "committed"
	case Uncertain:
		return "uncertain"
	}
	return "unknown"
}

// mintError is a Mint failure that came at or after the root replacement,
// with what it left the root selecting.
type mintError struct {
	outcome MintOutcome
	err     error
}

func (e *mintError) Error() string { return e.err.Error() }
func (e *mintError) Unwrap() error { return e.err }

// MintOutcomeOf reports what the Mint call that returned err left the store
// root selecting: Committed for a nil error, and for an error what Mint
// classified, NotCommitted when it failed before the root replacement. A
// caller whose mint failed treats anything but NotCommitted as a commit it
// cannot vouch for: the root may have moved, or did and something after it
// failed.
func MintOutcomeOf(err error) MintOutcome {
	if err == nil {
		return Committed
	}
	var failed *mintError
	if errors.As(err, &failed) {
		return failed.outcome
	}
	return NotCommitted
}

// replacesRoot reports whether the mint replaces the store root's keyring,
// which a request asks for by giving a successor keyring or passphrase.
func (req MintRequest) replacesRoot() bool {
	return req.ReplacementKeyring != nil || len(req.ReplacementPassphrase) != 0
}

// validate refuses a request whose fields do not fit together, before Mint
// reads or writes anything.
func (req MintRequest) validate() error {
	if err := storepaths.ValidateGenerationID(req.GenerationID); err != nil {
		return err
	}
	if req.Operation == "" || req.OperationID == "" {
		return fmt.Errorf("mint requires a durable operation identity")
	}
	if req.ValidateCandidate == nil && !req.SkipCandidateValidation {
		return fmt.Errorf("mint requires candidate validation")
	}
	if req.Integrity == nil {
		return fmt.Errorf("store-root mint requires an integrity keyring")
	}
	if req.FirstGeneration && len(req.InitialPassphrase) == 0 {
		return fmt.Errorf("store-root first mint requires an initial passphrase")
	}
	if req.OutgoingSealAlreadyWritten && req.Parent == "" {
		return fmt.Errorf("pre-sealed outgoing generation requires a parent")
	}
	replacingRoot := req.replacesRoot()
	if replacingRoot && (req.FirstGeneration || !req.OutgoingSealAlreadyWritten || req.ReplacementKeyring == nil || len(req.ReplacementPassphrase) == 0) {
		return fmt.Errorf("replacement root requires a successor, a pre-sealed outgoing generation, a successor keyring, and a passphrase")
	}
	return nil
}

// verifyFirstMint checks that a first mint is parentless and starts from a
// store with no root and no generation on disk: a missing root alone proves
// nothing, which is what verifyFirstMintPreconditions is for.
func verifyFirstMint(paths storepaths.Paths, req MintRequest) error {
	if req.Parent != "" {
		return fmt.Errorf("atomic store-root first mint must be parentless")
	}
	if _, err := os.Lstat(paths.StoreRootPath()); err == nil {
		return fmt.Errorf("mint: store root already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := verifyFirstMintPreconditions(paths); err != nil {
		return err
	}
	return nil
}

// verifySuccessorMint checks that the parent is the generation the
// authenticated store root names, and that the store can be minted from.
// requireMintableGenerationStore validates the parent as the current
// generation, its deleted archive limits included, so Mint does not inspect
// the parent's archive again.
func verifySuccessorMint(paths storepaths.Paths, req MintRequest) error {
	if req.Parent == "" {
		return fmt.Errorf("atomic store-root successor mint requires a parent")
	}
	selected, err := AuthenticateStoreRootSelection(paths, req.Integrity)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	if selected.GenerationID() != req.Parent {
		return fmt.Errorf(
			"mint parent %q is not the store-root current generation %s",
			req.Parent,
			selected.GenerationID(),
		)
	}
	if err := requireMintableGenerationStore(paths, req.Integrity); err != nil {
		return fmt.Errorf("mint preflight: %w", err)
	}
	if err := RequireSuccessorFits(paths.GenerationPaths(req.Parent)); err != nil {
		return fmt.Errorf("mint preflight: %w", err)
	}
	return nil
}

func bindRollbackCapability(seed *RollbackCapability, inventory []InventoryEntry) (*RollbackCapability, error) {
	if seed == nil {
		return nil, nil
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
// (docs/ARCH_STORE.md, "Recovery and restoration"), so the generations directory must
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
	authority, err := presentAuthorityFiles(from)
	if err != nil {
		return err
	}
	for _, relative := range authority {
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
		gen.PoliciesDir(),
		gen.SourceTokensDir(),
		gen.DeletedDir(),
		gen.DeletedKeysDir(),
		gen.DeletedKeyTypeRecordsDir(),
		gen.DeletedPoliciesDir(),
		gen.DeletedSourceTokensDir(),
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

// validateStagedStructure runs the structural validator against the
// unpublished staging root.
func validateStagedStructure(staged storepaths.GenPaths) error {
	if err := validateGenerationAuthorityShape(staged); err != nil {
		return err
	}
	entries, err := os.ReadDir(staged.Dir())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch name := entry.Name(); {
		case name == storepaths.GenerationManifestName:
		case name == storepaths.GenerationSealName:
			// Staged generations are pre-publish by definition; a seal
			// there means something wrote the final content record
			// before the generation ever became current. Never accept.
			return fmt.Errorf("staged generation %s carries a seal", staged.GenerationID())
		case slices.Contains(generationRootDirs, name), isAuthorityFileName(name):
			// Validated by validateGenerationAuthorityShape above.
		default:
			return fmt.Errorf("generation %s contains unsupported entry %q", staged.GenerationID(), name)
		}
	}
	return nil
}
