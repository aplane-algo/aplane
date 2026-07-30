// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"errors"
	"fmt"
	"math"
	"os"
	"slices"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// CompletionReport describes durable progress through the completion
// boundary. A non-nil report may accompany an error.
type CompletionReport struct {
	Resume                   *ResumeReport
	FinalEntries             int
	BaselineWritten          bool
	BaselineAlreadyCurrent   bool
	RootClosed               bool
	SnapshotRemoved          bool
	RecoveredClosedRoot      bool
	PreRootSnapshotDiscarded bool
}

// CompleteRotation resumes the pinned transformation, verifies a fresh final
// inventory, publishes any required clean-cutover baseline, atomically closes
// the pending root, and only then removes the now-unreferenced snapshot.
//
// The caller holds the identity mutation lock. A direct-filesystem mutation
// detected at either final scan leaves the root pending. A clean rollback
// cutover receives its post-rewrap baseline before close; a diverged cutover
// never receives a new baseline.
func CompleteRotation(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
	passphrase []byte,
) (*CompletionReport, error) {
	if kr == nil {
		return nil, fmt.Errorf("complete rotation: keyring is required")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("complete rotation: passphrase is required")
	}
	state, pending := kr.PendingRotation()
	if !pending {
		return cleanupUnreferencedRotationSnapshot(paths, identityID, kr, passphrase)
	}

	report := &CompletionReport{}
	resume, err := ResumeRotation(paths, identityID, kr)
	report.Resume = resume
	if err != nil {
		return report, err
	}
	snapshot, err := ReadReferencedSnapshot(
		paths,
		identityID,
		state.Snapshot,
		state.FromTerm,
		state.ToTerm,
		kr,
	)
	if err != nil {
		return report, err
	}
	historicalPrefixes, err := historicalGenerationPrefixes(paths, identityID, kr)
	if err != nil {
		return report, err
	}

	before, err := Scan(paths, identityID, kr)
	if err != nil {
		return report, fmt.Errorf("complete rotation pre-baseline scan: %w", err)
	}
	baseline, err := completionBaseline(snapshot, before)
	if err != nil {
		return report, err
	}
	if err := verifyCompletionInventory(
		paths,
		identityID,
		before,
		snapshot,
		state,
		historicalPrefixes,
		baseline,
		false,
		kr,
	); err != nil {
		return report, err
	}

	if baseline != nil {
		current, err := readMatchingCompletionBaseline(
			paths,
			identityID,
			baseline,
			kr,
		)
		if err != nil {
			return report, err
		}
		if current {
			report.BaselineAlreadyCurrent = true
		} else {
			if err := WriteBaseline(paths, identityID, baseline, kr); err != nil {
				return report, err
			}
			report.BaselineWritten = true
		}
	}

	after, err := Scan(paths, identityID, kr)
	if err != nil {
		return report, fmt.Errorf("complete rotation post-baseline scan: %w", err)
	}
	finalBaseline, err := completionBaseline(snapshot, after)
	if err != nil {
		return report, err
	}
	if err := verifyCompletionInventory(
		paths,
		identityID,
		after,
		snapshot,
		state,
		historicalPrefixes,
		finalBaseline,
		finalBaseline != nil,
		kr,
	); err != nil {
		return report, err
	}
	report.FinalEntries = len(after.Entries)

	if err := crypto.CloseRotation(
		paths.IdentityDir(identityID),
		kr,
		passphrase,
	); err != nil {
		if _, stillPending := kr.PendingRotation(); !stillPending {
			report.RootClosed = true
		}
		return report, err
	}
	report.RootClosed = true

	if err := fsutil.RemoveDurable(
		paths.RotationSnapshotPath(identityID),
	); err != nil {
		return report, fmt.Errorf("remove completed rotation snapshot: %w", err)
	}
	report.SnapshotRemoved = true
	return report, nil
}

func completionBaseline(
	snapshot *Snapshot,
	report *Report,
) (*Baseline, error) {
	if snapshot.Rollback == nil ||
		snapshot.Rollback.Decision == DecisionDiverged {
		return nil, nil
	}
	if snapshot.Rollback.Decision != DecisionClean {
		return nil, fmt.Errorf(
			"complete rotation has invalid rollback decision %q",
			snapshot.Rollback.Decision,
		)
	}
	if report.CurrentGeneration != snapshot.Rollback.GenerationID {
		return nil, fmt.Errorf(
			"complete rotation CURRENT %q does not match cutover generation %q",
			report.CurrentGeneration,
			snapshot.Rollback.GenerationID,
		)
	}
	return NewBaseline(report.CurrentGeneration, report.currentInventory)
}

func verifyCompletionInventory(
	paths storepaths.Paths,
	identityID string,
	final *Report,
	snapshot *Snapshot,
	state crypto.RotationState,
	historicalPrefixes []string,
	desiredBaseline *Baseline,
	requireDesiredBaseline bool,
	kr *crypto.Keyring,
) error {
	if final == nil {
		return fmt.Errorf("complete rotation requires a final inventory")
	}
	expected := make(map[string]Entry, len(snapshot.Inventory))
	for _, entry := range snapshot.Inventory {
		expected[entry.Path] = entry
	}
	snapshotPath, err := canonicalPathFor(
		paths,
		paths.RotationSnapshotPath(identityID),
	)
	if err != nil {
		return err
	}
	baselinePath, err := canonicalPathFor(
		paths,
		paths.RotationBaselinePath(identityID),
	)
	if err != nil {
		return err
	}
	snapshotSeen := false
	baselineWasPinned := false
	if entry, ok := expected[baselinePath]; ok {
		baselineWasPinned = entry.Kind == KindRotationBaseline
	}

	seen := make(map[string]struct{}, len(final.Entries))
	for _, actual := range final.Entries {
		if actual.Path == snapshotPath {
			if snapshotSeen {
				return fmt.Errorf("complete rotation final inventory duplicates snapshot")
			}
			snapshotSeen = true
			if actual.Kind != KindRotationSnapshot ||
				actual.Term != state.ToTerm ||
				actual.ObjectClass != crypto.ClassRotationSnapshot ||
				actual.ObjectSelector != crypto.RotationSnapshotContext().Selector ||
				actual.Size != state.Snapshot.Size ||
				actual.SHA256 != state.Snapshot.SHA256 {
				return fmt.Errorf(
					"complete rotation snapshot no longer matches the pending root reference",
				)
			}
			continue
		}
		pinned, ok := expected[actual.Path]
		if !ok {
			if actual.Path == baselinePath &&
				desiredBaseline != nil &&
				!baselineWasPinned {
				continue
			}
			return fmt.Errorf(
				"complete rotation found unpinned path %q",
				actual.Path,
			)
		}
		if err := verifyCompletionEntry(
			pinned,
			actual,
			state.ToTerm,
			historicalPrefixes,
		); err != nil {
			return err
		}
		seen[actual.Path] = struct{}{}
	}
	if !snapshotSeen {
		return fmt.Errorf("complete rotation final inventory omitted the referenced snapshot")
	}
	for path := range expected {
		if _, ok := seen[path]; !ok {
			return fmt.Errorf("complete rotation final inventory omitted pinned path %q", path)
		}
	}

	if desiredBaseline != nil {
		_, statErr := os.Lstat(paths.RotationBaselinePath(identityID))
		switch {
		case statErr == nil:
			matches, err := readMatchingCompletionBaseline(
				paths,
				identityID,
				desiredBaseline,
				kr,
			)
			if err != nil {
				return err
			}
			if (requireDesiredBaseline || !baselineWasPinned) && !matches {
				return fmt.Errorf(
					"complete rotation baseline does not match the final generation inventory",
				)
			}
		case errors.Is(statErr, os.ErrNotExist):
			if requireDesiredBaseline {
				return fmt.Errorf("complete rotation required baseline is missing")
			}
		default:
			return fmt.Errorf("complete rotation baseline status: %w", statErr)
		}
	}
	return nil
}

func verifyCompletionEntry(
	pinned, actual Entry,
	targetTerm int64,
	historicalPrefixes []string,
) error {
	if hasCanonicalPrefix(pinned.Path, historicalPrefixes) {
		if actual != pinned {
			return fmt.Errorf(
				"complete rotation historical entry %q changed from its snapshot",
				pinned.Path,
			)
		}
		return nil
	}
	switch {
	case pinned.ObjectClass != "":
		if actual.Path != pinned.Path ||
			actual.Kind != pinned.Kind ||
			actual.Term != targetTerm ||
			actual.ObjectClass != pinned.ObjectClass ||
			actual.ObjectSelector != pinned.ObjectSelector {
			return fmt.Errorf(
				"complete rotation envelope %q does not have pinned target authority",
				pinned.Path,
			)
		}
	case pinned.Kind == KindPolicySidecar ||
		pinned.Kind == KindNodeRoleSidecar:
		if actual.Path != pinned.Path ||
			actual.Kind != pinned.Kind ||
			actual.Term != targetTerm ||
			actual.ObjectClass != "" ||
			actual.ObjectSelector != "" {
			return fmt.Errorf(
				"complete rotation sidecar %q does not have target authority",
				pinned.Path,
			)
		}
	default:
		if actual != pinned {
			return fmt.Errorf(
				"complete rotation plaintext entry %q changed from its snapshot",
				pinned.Path,
			)
		}
	}
	return nil
}

func readMatchingCompletionBaseline(
	paths storepaths.Paths,
	identityID string,
	want *Baseline,
	kr *crypto.Keyring,
) (bool, error) {
	if kr == nil {
		return false, fmt.Errorf("complete rotation baseline requires a keyring")
	}
	got, err := ReadBaseline(paths, identityID, kr)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("complete rotation baseline: %w", err)
	}
	return *got == *want, nil
}

func cleanupUnreferencedRotationSnapshot(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
	passphrase []byte,
) (*CompletionReport, error) {
	report := &CompletionReport{}
	snapshotPath := paths.RotationSnapshotPath(identityID)
	sealed, err := readSnapshotFile(snapshotPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoRotationPending
	}
	if err != nil {
		return report, fmt.Errorf("read unreferenced rotation snapshot: %w", err)
	}
	term, err := crypto.EnvelopeTerm(sealed)
	if err != nil {
		return report, fmt.Errorf("unreferenced rotation snapshot term: %w", err)
	}

	onDisk, err := crypto.OpenKeyringStore(
		paths.IdentityDir(identityID),
		passphrase,
	)
	if err != nil {
		return report, fmt.Errorf("reopen settled rotation root: %w", err)
	}
	defer onDisk.Zero()
	if _, pending := onDisk.PendingRotation(); pending ||
		onDisk.CurrentTerm() != kr.CurrentTerm() ||
		!slices.Equal(
			onDisk.HistoricalGenerationAnchors(),
			kr.HistoricalGenerationAnchors(),
		) {
		return report, fmt.Errorf(
			"visible rotation root does not match the settled in-memory authority",
		)
	}

	switch {
	case term == kr.CurrentTerm():
		plaintext, err := kr.Open(sealed, crypto.RotationSnapshotContext())
		if err != nil {
			return report, fmt.Errorf("open unreferenced rotation snapshot: %w", err)
		}
		snapshot, parseErr := ParseSnapshot(plaintext)
		crypto.ZeroBytes(plaintext)
		if parseErr != nil {
			return report, parseErr
		}
		if snapshot.ToTerm != kr.CurrentTerm() {
			return report, fmt.Errorf(
				"unreferenced rotation snapshot target term %d does not match settled current term %d",
				snapshot.ToTerm,
				kr.CurrentTerm(),
			)
		}
		diskPlaintext, err := onDisk.Open(
			sealed,
			crypto.RotationSnapshotContext(),
		)
		if err != nil {
			return report, fmt.Errorf(
				"unreferenced snapshot does not authenticate under the visible settled root: %w",
				err,
			)
		}
		crypto.ZeroBytes(diskPlaintext)
		report.RootClosed = true
		report.RecoveredClosedRoot = true
	case kr.CurrentTerm() < math.MaxInt64 &&
		term == kr.CurrentTerm()+1:
		// The snapshot is the durable first half of StartRotation, but the
		// settled root proves its publication never committed. Its target
		// key is therefore absent and the envelope cannot be authenticated;
		// the root's lack of a descriptor is the authority to discard this
		// reserved, unreferenced artifact.
		report.PreRootSnapshotDiscarded = true
	default:
		return report, fmt.Errorf(
			"unreferenced rotation snapshot term %d is incompatible with settled current term %d",
			term,
			kr.CurrentTerm(),
		)
	}

	if err := fsutil.SyncDir(paths.IdentityDir(identityID)); err != nil {
		return report, fmt.Errorf("sync settled rotation root directory: %w", err)
	}
	if err := fsutil.RemoveDurable(snapshotPath); err != nil {
		return report, fmt.Errorf("remove unreferenced rotation snapshot: %w", err)
	}
	report.SnapshotRemoved = true
	return report, nil
}
