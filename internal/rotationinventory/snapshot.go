// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	// SnapshotSchema identifies the plaintext inside rotation.snapshot.enc.
	SnapshotSchema = "aplane.rotation-snapshot.v1"

	// AuthorityGenerationManifest names the immutable at-mint inventory as
	// the effective rollback-divergence authority at cutover.
	AuthorityGenerationManifest InventoryAuthoritySource = "generation-manifest"
	// AuthorityRotationBaseline names a prior authenticated rotation
	// baseline as the effective rollback-divergence authority at cutover.
	AuthorityRotationBaseline InventoryAuthoritySource = "rotation-baseline"

	// DecisionClean records that the current generation matched its effective
	// authority before any rewrap.
	DecisionClean RollbackDecision = "clean"
	// DecisionDiverged records that it did not match before any rewrap.
	DecisionDiverged RollbackDecision = "diverged"
)

// Snapshot is the authenticated cutover input. Its inventory pins the exact
// files a transition may consume; it never contains its own encrypted file.
type Snapshot struct {
	Schema    string           `json:"schema"`
	FromTerm  int64            `json:"from_term"`
	ToTerm    int64            `json:"to_term"`
	Inventory []Entry          `json:"inventory"`
	Rollback  *RollbackCutover `json:"rollback,omitempty"`
}

// RollbackDecision is the pre-rewrap clean-or-diverged decision.
type RollbackDecision string

// InventoryAuthoritySource identifies which durable record supplied the
// effective starting inventory used by the rollback divergence guard.
type InventoryAuthoritySource string

// InventoryAuthority pins a generation inventory independently of JSON
// formatting. EntryCount may be zero for an empty first generation.
type InventoryAuthority struct {
	Source          InventoryAuthoritySource `json:"source"`
	EntryCount      int64                    `json:"entry_count"`
	InventorySHA256 string                   `json:"inventory_sha256"`
}

// RollbackCutover preserves the decision made before rewrap so resume cannot
// reinterpret partially transformed ciphertext as a new clean baseline.
type RollbackCutover struct {
	GenerationID string             `json:"generation_id"`
	Decision     RollbackDecision   `json:"decision"`
	Authority    InventoryAuthority `json:"authority"`
}

// NewSnapshot copies a settled-store report into a strict cutover body.
func NewSnapshot(
	report *Report,
	fromTerm, toTerm int64,
	rollback *RollbackCutover,
) (*Snapshot, error) {
	if report == nil {
		return nil, fmt.Errorf("rotation snapshot requires an inventory report")
	}
	if rollback != nil && rollback.GenerationID != report.CurrentGeneration {
		return nil, fmt.Errorf(
			"rollback generation %q does not match CURRENT %q",
			rollback.GenerationID,
			report.CurrentGeneration,
		)
	}
	snapshot := &Snapshot{
		Schema:    SnapshotSchema,
		FromTerm:  fromTerm,
		ToTerm:    toTerm,
		Inventory: slices.Clone(report.Entries),
		Rollback:  cloneRollback(rollback),
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// ManifestAuthority creates the rollback authority named by an at-mint
// generation manifest.
func ManifestAuthority(manifest *genstore.Manifest) (InventoryAuthority, error) {
	if manifest == nil {
		return InventoryAuthority{}, fmt.Errorf("missing generation manifest")
	}
	digest, err := genstore.CanonicalInventoryDigest(manifest.Inventory)
	if err != nil {
		return InventoryAuthority{}, fmt.Errorf("manifest inventory: %w", err)
	}
	return InventoryAuthority{
		Source:          AuthorityGenerationManifest,
		EntryCount:      int64(len(manifest.Inventory)),
		InventorySHA256: digest,
	}, nil
}

// ValidateSnapshot enforces the strict plaintext schema and K8 entry
// invariants before the body is sealed or after it is opened.
func ValidateSnapshot(snapshot *Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("missing rotation snapshot")
	}
	if snapshot.Schema != SnapshotSchema {
		return fmt.Errorf("unsupported rotation snapshot schema %q", snapshot.Schema)
	}
	if snapshot.FromTerm < crypto.FirstTerm ||
		snapshot.FromTerm == math.MaxInt64 ||
		snapshot.ToTerm != snapshot.FromTerm+1 {
		return fmt.Errorf(
			"rotation snapshot terms %d -> %d are not consecutive positive terms",
			snapshot.FromTerm,
			snapshot.ToTerm,
		)
	}
	if snapshot.Inventory == nil {
		return fmt.Errorf("rotation snapshot inventory must be an array")
	}
	if err := ValidateEntries(snapshot.Inventory); err != nil {
		return fmt.Errorf("rotation snapshot inventory: %w", err)
	}
	for _, entry := range snapshot.Inventory {
		if entry.Kind == KindRotationSnapshot {
			return fmt.Errorf("rotation snapshot recursively inventories %q", entry.Path)
		}
		if entry.Term > snapshot.FromTerm {
			return fmt.Errorf(
				"rotation snapshot entry %q names future term %d beyond from_term %d",
				entry.Path,
				entry.Term,
				snapshot.FromTerm,
			)
		}
	}
	if snapshot.Rollback != nil {
		if err := validateRollback(snapshot.Rollback); err != nil {
			return err
		}
		if err := validateRollbackInputs(snapshot); err != nil {
			return err
		}
	}
	return nil
}

// MarshalSnapshot returns the stable plaintext JSON sealed into the snapshot
// envelope. The encrypted file, not this plaintext, is what the root pins.
func MarshalSnapshot(snapshot *Snapshot) ([]byte, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal rotation snapshot: %w", err)
	}
	data = append(data, '\n')
	if len(data) > crypto.MaxRotationSnapshotBytes {
		return nil, fmt.Errorf(
			"rotation snapshot plaintext exceeds size limit %d",
			crypto.MaxRotationSnapshotBytes,
		)
	}
	return data, nil
}

// ParseSnapshot parses and validates exact opened plaintext bytes.
func ParseSnapshot(data []byte) (*Snapshot, error) {
	if len(data) > crypto.MaxRotationSnapshotBytes {
		return nil, fmt.Errorf(
			"rotation snapshot plaintext exceeds size limit %d",
			crypto.MaxRotationSnapshotBytes,
		)
	}
	var snapshot Snapshot
	if err := decodeSnapshotJSONStrict(data, &snapshot); err != nil {
		return nil, fmt.Errorf("parse rotation snapshot: %w", err)
	}
	if err := ValidateSnapshot(&snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// WriteSnapshot seals a validated body under its target term and durably
// publishes the exact encrypted file before any root may reference it.
func WriteSnapshot(
	paths storepaths.Paths,
	identityID string,
	snapshot *Snapshot,
	kr *crypto.Keyring,
) (crypto.RotationSnapshotReference, error) {
	if kr == nil {
		return crypto.RotationSnapshotReference{}, fmt.Errorf("write rotation snapshot: keyring is required")
	}
	if snapshot == nil || snapshot.ToTerm != kr.CurrentTerm() {
		return crypto.RotationSnapshotReference{}, fmt.Errorf(
			"write rotation snapshot: target term does not match keyring current term",
		)
	}
	plaintext, err := MarshalSnapshot(snapshot)
	if err != nil {
		return crypto.RotationSnapshotReference{}, err
	}
	defer crypto.ZeroBytes(plaintext)
	sealed, err := kr.Seal(plaintext, crypto.RotationSnapshotContext())
	if err != nil {
		return crypto.RotationSnapshotReference{}, fmt.Errorf("seal rotation snapshot: %w", err)
	}
	ref, err := crypto.NewRotationSnapshotReference(sealed)
	if err != nil {
		return crypto.RotationSnapshotReference{}, fmt.Errorf("seal rotation snapshot: %w", err)
	}
	if err := fsutil.WriteFileDurable(paths.RotationSnapshotPath(identityID), sealed); err != nil {
		return crypto.RotationSnapshotReference{}, fmt.Errorf("write rotation snapshot: %w", err)
	}
	return ref, nil
}

// ReadReferencedSnapshot loads at most the independent snapshot cap, verifies
// the root's exact file reference, opens that same buffer under the fixed
// logical context, and validates the expected transition terms.
func ReadReferencedSnapshot(
	paths storepaths.Paths,
	identityID string,
	ref crypto.RotationSnapshotReference,
	fromTerm, toTerm int64,
	kr *crypto.Keyring,
) (*Snapshot, error) {
	if kr == nil {
		return nil, fmt.Errorf("read rotation snapshot: keyring is required")
	}
	sealed, err := readSnapshotFile(paths.RotationSnapshotPath(identityID))
	if err != nil {
		return nil, fmt.Errorf("read rotation snapshot: %w", err)
	}
	if err := ref.VerifyExact(sealed); err != nil {
		return nil, fmt.Errorf("read rotation snapshot root reference: %w", err)
	}
	term, err := crypto.EnvelopeTerm(sealed)
	if err != nil {
		return nil, fmt.Errorf("read rotation snapshot term: %w", err)
	}
	if term != toTerm {
		return nil, fmt.Errorf(
			"rotation snapshot envelope term %d does not match target term %d",
			term,
			toTerm,
		)
	}
	plaintext, err := kr.Open(sealed, crypto.RotationSnapshotContext())
	if err != nil {
		return nil, fmt.Errorf("open rotation snapshot: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)
	snapshot, err := ParseSnapshot(plaintext)
	if err != nil {
		return nil, err
	}
	if snapshot.FromTerm != fromTerm || snapshot.ToTerm != toTerm {
		return nil, fmt.Errorf(
			"rotation snapshot transition %d -> %d does not match root transition %d -> %d",
			snapshot.FromTerm,
			snapshot.ToTerm,
			fromTerm,
			toTerm,
		)
	}
	return snapshot, nil
}

func validateRollback(rollback *RollbackCutover) error {
	if err := storepaths.ValidateGenerationID(rollback.GenerationID); err != nil {
		return fmt.Errorf("rotation snapshot rollback: %w", err)
	}
	switch rollback.Decision {
	case DecisionClean, DecisionDiverged:
	default:
		return fmt.Errorf("rotation snapshot rollback has invalid decision %q", rollback.Decision)
	}
	switch rollback.Authority.Source {
	case AuthorityGenerationManifest, AuthorityRotationBaseline:
	default:
		return fmt.Errorf(
			"rotation snapshot rollback has invalid authority source %q",
			rollback.Authority.Source,
		)
	}
	if rollback.Authority.EntryCount < 0 {
		return fmt.Errorf("rotation snapshot rollback authority has negative entry_count")
	}
	if err := validateSHA256(rollback.Authority.InventorySHA256); err != nil {
		return fmt.Errorf("rotation snapshot rollback inventory_sha256: %w", err)
	}
	return nil
}

func validateRollbackInputs(snapshot *Snapshot) error {
	rollback := snapshot.Rollback
	manifestSuffix := "/generations/" + rollback.GenerationID + "/" +
		storepaths.GenerationManifestName
	hasManifest := slices.ContainsFunc(snapshot.Inventory, func(entry Entry) bool {
		return entry.Kind == KindGenerationManifest &&
			strings.HasSuffix(entry.Path, manifestSuffix)
	})
	if !hasManifest {
		return fmt.Errorf(
			"rotation snapshot rollback generation %s has no pinned manifest",
			rollback.GenerationID,
		)
	}
	if rollback.Authority.Source == AuthorityRotationBaseline &&
		!slices.ContainsFunc(snapshot.Inventory, func(entry Entry) bool {
			return entry.Kind == KindRotationBaseline
		}) {
		return fmt.Errorf("rotation snapshot baseline authority has no pinned baseline input")
	}
	return nil
}

func cloneRollback(rollback *RollbackCutover) *RollbackCutover {
	if rollback == nil {
		return nil
	}
	cloned := *rollback
	return &cloned
}

func readSnapshotFile(path string) ([]byte, error) {
	data, _, err := fsutil.ReadRegularFileLimited(path, crypto.MaxRotationSnapshotBytes)
	if err != nil {
		return nil, fmt.Errorf("bounded snapshot read: %w", err)
	}
	return data, nil
}

func decodeSnapshotJSONStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	switch err := decoder.Decode(&trailing); err {
	case io.EOF:
		return nil
	case nil:
		return fmt.Errorf("trailing data after JSON document")
	default:
		return fmt.Errorf("trailing data after JSON document: %w", err)
	}
}
