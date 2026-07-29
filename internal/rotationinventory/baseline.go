// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	// BaselineSchema identifies the plaintext inside rotation.baseline.enc.
	BaselineSchema = "aplane.rotation-baseline.v1"

	// MaxRotationBaselineBytes bounds both plaintext parsing and the exact
	// encrypted baseline file. The schema is fixed-size; this leaves ample
	// encoding headroom without permitting an attacker-controlled large read.
	MaxRotationBaselineBytes int64 = 4 << 10
)

// Baseline is the authenticated post-rewrap inventory authority for one
// rollback-eligible generation. It intentionally stores only the canonical
// inventory digest rather than the inventory itself.
type Baseline struct {
	Schema          string `json:"schema"`
	GenerationID    string `json:"generation_id"`
	EntryCount      int64  `json:"entry_count"`
	InventorySHA256 string `json:"inventory_sha256"`
}

// NewBaseline records one generation's canonical live inventory after a
// successful rewrap.
func NewBaseline(
	generationID string,
	inventory []genstore.InventoryEntry,
) (*Baseline, error) {
	digest, err := genstore.CanonicalInventoryDigest(inventory)
	if err != nil {
		return nil, fmt.Errorf("rotation baseline inventory: %w", err)
	}
	baseline := &Baseline{
		Schema:          BaselineSchema,
		GenerationID:    generationID,
		EntryCount:      int64(len(inventory)),
		InventorySHA256: digest,
	}
	if err := ValidateBaseline(baseline); err != nil {
		return nil, err
	}
	return baseline, nil
}

// ValidateBaseline enforces the fixed plaintext record shape.
func ValidateBaseline(baseline *Baseline) error {
	if baseline == nil {
		return fmt.Errorf("missing rotation baseline")
	}
	if baseline.Schema != BaselineSchema {
		return fmt.Errorf("unsupported rotation baseline schema %q", baseline.Schema)
	}
	if err := storepaths.ValidateGenerationID(baseline.GenerationID); err != nil {
		return fmt.Errorf("rotation baseline: %w", err)
	}
	if baseline.EntryCount < 0 {
		return fmt.Errorf("rotation baseline has negative entry_count")
	}
	if err := validateSHA256(baseline.InventorySHA256); err != nil {
		return fmt.Errorf("rotation baseline inventory_sha256: %w", err)
	}
	return nil
}

// MarshalBaseline returns the stable plaintext JSON sealed into the baseline
// envelope.
func MarshalBaseline(baseline *Baseline) ([]byte, error) {
	if err := ValidateBaseline(baseline); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal rotation baseline: %w", err)
	}
	data = append(data, '\n')
	if int64(len(data)) > MaxRotationBaselineBytes {
		return nil, fmt.Errorf(
			"rotation baseline plaintext exceeds size limit %d",
			MaxRotationBaselineBytes,
		)
	}
	return data, nil
}

// ParseBaseline strictly parses exact opened plaintext bytes. The pointer on
// EntryCount distinguishes a required zero from an omitted or null field.
func ParseBaseline(data []byte) (*Baseline, error) {
	if int64(len(data)) > MaxRotationBaselineBytes {
		return nil, fmt.Errorf(
			"rotation baseline plaintext exceeds size limit %d",
			MaxRotationBaselineBytes,
		)
	}
	var wire struct {
		Schema          string `json:"schema"`
		GenerationID    string `json:"generation_id"`
		EntryCount      *int64 `json:"entry_count"`
		InventorySHA256 string `json:"inventory_sha256"`
	}
	if err := decodeRotationJSONStrict(data, &wire); err != nil {
		return nil, fmt.Errorf("parse rotation baseline: %w", err)
	}
	if wire.EntryCount == nil {
		return nil, fmt.Errorf("rotation baseline entry_count is required")
	}
	baseline := &Baseline{
		Schema:          wire.Schema,
		GenerationID:    wire.GenerationID,
		EntryCount:      *wire.EntryCount,
		InventorySHA256: wire.InventorySHA256,
	}
	if err := ValidateBaseline(baseline); err != nil {
		return nil, err
	}
	return baseline, nil
}

// BaselineAuthority projects a validated record into the rollback authority
// carried by a cutover snapshot.
func BaselineAuthority(baseline *Baseline) (InventoryAuthority, error) {
	if err := ValidateBaseline(baseline); err != nil {
		return InventoryAuthority{}, err
	}
	return InventoryAuthority{
		Source:          AuthorityRotationBaseline,
		EntryCount:      baseline.EntryCount,
		InventorySHA256: baseline.InventorySHA256,
	}, nil
}

// EvaluateRollbackCutover records the pre-rewrap clean/diverged decision
// against the effective authority. A matching prior baseline supersedes the
// at-mint manifest; a baseline for any other generation is never authority.
func EvaluateRollbackCutover(
	generationID string,
	live []genstore.InventoryEntry,
	manifest *genstore.Manifest,
	baseline *Baseline,
) (*RollbackCutover, error) {
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, fmt.Errorf("rollback cutover requires a generation manifest")
	}
	if manifest.GenerationID != generationID {
		return nil, fmt.Errorf(
			"rollback manifest names generation %q, want %q",
			manifest.GenerationID,
			generationID,
		)
	}

	authority, err := ManifestAuthority(manifest)
	if err != nil {
		return nil, err
	}
	if baseline != nil {
		if err := ValidateBaseline(baseline); err != nil {
			return nil, err
		}
		if baseline.GenerationID != generationID {
			return nil, fmt.Errorf(
				"rotation baseline names generation %q, want %q",
				baseline.GenerationID,
				generationID,
			)
		}
		authority, err = BaselineAuthority(baseline)
		if err != nil {
			return nil, err
		}
	}

	liveDigest, err := genstore.CanonicalInventoryDigest(live)
	if err != nil {
		return nil, fmt.Errorf("live rollback inventory: %w", err)
	}
	decision := DecisionDiverged
	if int64(len(live)) == authority.EntryCount &&
		liveDigest == authority.InventorySHA256 {
		decision = DecisionClean
	}
	return &RollbackCutover{
		GenerationID: generationID,
		Decision:     decision,
		Authority:    authority,
	}, nil
}

// WriteBaseline seals a validated completion record under the current term
// and durably publishes it before a pending rotation may be cleared.
func WriteBaseline(
	paths storepaths.Paths,
	identityID string,
	baseline *Baseline,
	kr *crypto.Keyring,
) error {
	if kr == nil {
		return fmt.Errorf("write rotation baseline: keyring is required")
	}
	plaintext, err := MarshalBaseline(baseline)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(plaintext)
	sealed, err := kr.Seal(plaintext, crypto.RotationBaselineContext())
	if err != nil {
		return fmt.Errorf("seal rotation baseline: %w", err)
	}
	if int64(len(sealed)) > MaxRotationBaselineBytes {
		return fmt.Errorf(
			"encrypted rotation baseline exceeds size limit %d",
			MaxRotationBaselineBytes,
		)
	}
	if err := fsutil.WriteFileDurable(paths.RotationBaselinePath(identityID), sealed); err != nil {
		return fmt.Errorf("write rotation baseline: %w", err)
	}
	return nil
}

// ReadBaseline opens and validates the exact bounded baseline file under the
// current term and its fixed logical context.
func ReadBaseline(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
) (*Baseline, error) {
	if kr == nil {
		return nil, fmt.Errorf("read rotation baseline: keyring is required")
	}
	sealed, _, err := fsutil.ReadRegularFileLimited(
		paths.RotationBaselinePath(identityID),
		MaxRotationBaselineBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read rotation baseline: %w", err)
	}
	baseline, err := openBaselineBytes(sealed, kr)
	if err != nil {
		return nil, fmt.Errorf("read rotation baseline: %w", err)
	}
	return baseline, nil
}

func openBaselineBytes(sealed []byte, kr *crypto.Keyring) (*Baseline, error) {
	if kr == nil {
		return nil, fmt.Errorf("keyring is required")
	}
	if int64(len(sealed)) > MaxRotationBaselineBytes {
		return nil, fmt.Errorf(
			"encrypted file exceeds size limit %d",
			MaxRotationBaselineBytes,
		)
	}
	term, err := crypto.EnvelopeTerm(sealed)
	if err != nil {
		return nil, fmt.Errorf("envelope term: %w", err)
	}
	if term != kr.CurrentTerm() {
		return nil, fmt.Errorf(
			"envelope term %d does not match current term %d",
			term,
			kr.CurrentTerm(),
		)
	}
	plaintext, err := kr.Open(sealed, crypto.RotationBaselineContext())
	if err != nil {
		return nil, fmt.Errorf("open fixed context: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)
	return ParseBaseline(plaintext)
}

// ReconcileBaselineForPreflight returns a valid baseline for CURRENT, removes
// a valid stale baseline durably, and preserves malformed or unauthorized
// files as blocking evidence for operator remediation.
func ReconcileBaselineForPreflight(
	paths storepaths.Paths,
	identityID, currentGeneration string,
	kr *crypto.Keyring,
) (*Baseline, error) {
	if err := storepaths.ValidateGenerationID(currentGeneration); err != nil {
		return nil, err
	}
	baseline, err := ReadBaseline(paths, identityID, kr)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reconcile rotation baseline: %w", err)
	}
	if baseline.GenerationID == currentGeneration {
		return baseline, nil
	}
	if err := fsutil.RemoveDurable(paths.RotationBaselinePath(identityID)); err != nil {
		return nil, fmt.Errorf("remove stale rotation baseline: %w", err)
	}
	return nil, nil
}
