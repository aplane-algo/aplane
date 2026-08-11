// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const rewrapOutputSizeAllowance int64 = 4 << 10

// ErrNoRotationPending reports that resume or completion was requested for a
// settled root.
var ErrNoRotationPending = crypto.ErrNoRotationPending

// ResumeReport describes one idempotent pass over the root-pinned snapshot.
// A non-nil report may accompany an error and records the durable progress
// completed before that failure.
type ResumeReport struct {
	SnapshotEntries          int
	Rewrapped                int
	Resigned                 int
	AlreadyTarget            int
	VerifiedUnchanged        int
	KeysMigrated             int
	TemplatesMigrated        int
	PolicySidecarsMigrated   int
	NodeRoleSidecarsMigrated int
}

// ResumeRotation rewraps snapshot-pinned mutable consumers onto the target
// term and re-signs live integrity sidecars. It deliberately does not write a
// completion baseline, clear the pending root, or remove the snapshot.
//
// The caller holds the identity mutation lock. Every retiring-term input must
// still match the snapshot's exact bytes. A target-term output is accepted on
// retry only after context-bound authentication (or sidecar verification)
// succeeds. Retained anchored generations are immutable and remain byte-for-
// byte on their historical terms.
func ResumeRotation(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
) (*ResumeReport, error) {
	if kr == nil {
		return nil, fmt.Errorf("resume rotation: keyring is required")
	}
	state, pending := kr.PendingRotation()
	if !pending {
		return nil, ErrNoRotationPending
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
		return nil, err
	}
	historicalPrefixes, err := historicalGenerationPrefixes(paths, identityID, kr)
	if err != nil {
		return nil, err
	}
	entriesByKind := make(map[ArtifactKind][]Entry)
	for _, entry := range snapshot.Inventory {
		entriesByKind[entry.Kind] = append(entriesByKind[entry.Kind], entry)
	}
	if err := validateIntegrityPairs(paths, identityID, entriesByKind); err != nil {
		return nil, err
	}

	report := &ResumeReport{SnapshotEntries: len(snapshot.Inventory)}
	for _, entry := range snapshot.Inventory {
		historical := hasCanonicalPrefix(entry.Path, historicalPrefixes)
		switch {
		case historical:
			if err := verifyPinnedEntry(paths, entry); err != nil {
				return report, fmt.Errorf(
					"resume rotation immutable historical entry %q: %w",
					entry.Path,
					err,
				)
			}
			report.VerifiedUnchanged++
		case entry.Kind == KindPolicySidecar:
			document := entriesByKind[KindPolicyDocument][0]
			if err := resumePolicySidecar(paths, entry, document, kr, state, report); err != nil {
				return report, err
			}
		case entry.Kind == KindNodeRoleSidecar:
			document := entriesByKind[KindNodeRoleDocument][0]
			if err := resumeNodeRoleSidecar(paths, entry, document, kr, state, report); err != nil {
				return report, err
			}
		case entry.ObjectClass != "":
			if err := resumeEnvelope(paths, entry, kr, state, report); err != nil {
				return report, err
			}
		default:
			if err := verifyPinnedEntry(paths, entry); err != nil {
				return report, fmt.Errorf(
					"resume rotation unchanged entry %q: %w",
					entry.Path,
					err,
				)
			}
			report.VerifiedUnchanged++
		}
		if !historical {
			countMigrationTarget(report, entry.Kind)
		}
	}
	return report, nil
}

func countMigrationTarget(report *ResumeReport, kind ArtifactKind) {
	switch kind {
	case KindAccountKey, KindSentryCredential:
		report.KeysMigrated++
	case KindKeyTypeTemplate:
		report.TemplatesMigrated++
	case KindPolicySidecar:
		report.PolicySidecarsMigrated++
	case KindNodeRoleSidecar:
		report.NodeRoleSidecarsMigrated++
	}
}

func resumeEnvelope(
	paths storepaths.Paths,
	entry Entry,
	kr *crypto.Keyring,
	state crypto.RotationState,
	report *ResumeReport,
) error {
	data, err := readResumeEntry(paths, entry, true)
	if err != nil {
		return fmt.Errorf("resume rotation read %q: %w", entry.Path, err)
	}
	term, err := crypto.EnvelopeTerm(data)
	if err != nil {
		return fmt.Errorf("resume rotation envelope %q: %w", entry.Path, err)
	}
	ctx := crypto.ObjectContext{
		Class:    entry.ObjectClass,
		Selector: entry.ObjectSelector,
	}
	switch term {
	case state.ToTerm:
		plaintext, err := kr.Open(data, ctx)
		if err != nil {
			return fmt.Errorf(
				"resume rotation authenticate target output %q: %w",
				entry.Path,
				err,
			)
		}
		crypto.ZeroBytes(plaintext)
		report.AlreadyTarget++
		return nil
	case state.FromTerm:
		if err := verifyPinnedBytes(entry, data); err != nil {
			return fmt.Errorf(
				"resume rotation pinned input %q: %w",
				entry.Path,
				err,
			)
		}
	default:
		return fmt.Errorf(
			"resume rotation entry %q has unauthorized term %d, want retiring %d or target %d",
			entry.Path,
			term,
			state.FromTerm,
			state.ToTerm,
		)
	}

	plaintext, err := kr.Open(data, ctx)
	if err != nil {
		return fmt.Errorf("resume rotation open pinned input %q: %w", entry.Path, err)
	}
	defer crypto.ZeroBytes(plaintext)
	sealed, err := kr.Seal(plaintext, ctx)
	if err != nil {
		return fmt.Errorf("resume rotation seal target output %q: %w", entry.Path, err)
	}
	path, err := resolveResumePath(paths, entry.Path)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(path, sealed); err != nil {
		return fmt.Errorf("resume rotation write target output %q: %w", entry.Path, err)
	}
	report.Rewrapped++
	return nil
}

func resumePolicySidecar(
	paths storepaths.Paths,
	sidecarEntry, documentEntry Entry,
	kr *crypto.Keyring,
	state crypto.RotationState,
	report *ResumeReport,
) error {
	documentBytes, err := readPinnedDocument(paths, documentEntry)
	if err != nil {
		return fmt.Errorf("resume rotation policy document: %w", err)
	}
	sidecarBytes, err := readResumeEntry(paths, sidecarEntry, true)
	if err != nil {
		return fmt.Errorf("resume rotation policy sidecar: %w", err)
	}
	sidecar, err := policy.ParsePolicyIntegritySidecar(sidecarBytes)
	if err != nil {
		return fmt.Errorf("resume rotation policy sidecar: %w", err)
	}
	switch sidecar.IntegrityTerm {
	case state.ToTerm:
		if err := policy.VerifyPolicyIntegrity(documentBytes, sidecar, kr); err != nil {
			return fmt.Errorf("resume rotation authenticate target policy sidecar: %w", err)
		}
		report.AlreadyTarget++
		return nil
	case state.FromTerm:
		if err := verifyPinnedBytes(sidecarEntry, sidecarBytes); err != nil {
			return fmt.Errorf("resume rotation pinned policy sidecar: %w", err)
		}
		if err := policy.VerifyPolicyIntegrity(documentBytes, sidecar, kr); err != nil {
			return fmt.Errorf("resume rotation verify pinned policy sidecar: %w", err)
		}
	default:
		return fmt.Errorf(
			"resume rotation policy sidecar has unauthorized term %d, want retiring %d or target %d",
			sidecar.IntegrityTerm,
			state.FromTerm,
			state.ToTerm,
		)
	}
	target, err := policy.SignPolicyIntegrity(documentBytes, kr, time.Now())
	if err != nil {
		return fmt.Errorf("resume rotation sign policy sidecar: %w", err)
	}
	encoded, err := policy.MarshalPolicyIntegritySidecar(target)
	if err != nil {
		return fmt.Errorf("resume rotation marshal policy sidecar: %w", err)
	}
	path, err := resolveResumePath(paths, sidecarEntry.Path)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(path, encoded); err != nil {
		return fmt.Errorf("resume rotation write policy sidecar: %w", err)
	}
	report.Resigned++
	return nil
}

func resumeNodeRoleSidecar(
	paths storepaths.Paths,
	sidecarEntry, documentEntry Entry,
	kr *crypto.Keyring,
	state crypto.RotationState,
	report *ResumeReport,
) error {
	documentBytes, err := readPinnedDocument(paths, documentEntry)
	if err != nil {
		return fmt.Errorf("resume rotation node-role document: %w", err)
	}
	sidecarBytes, err := readResumeEntry(paths, sidecarEntry, true)
	if err != nil {
		return fmt.Errorf("resume rotation node-role sidecar: %w", err)
	}
	sidecar, err := noderole.ParseSidecar(sidecarBytes)
	if err != nil {
		return fmt.Errorf("resume rotation node-role sidecar: %w", err)
	}
	switch sidecar.IntegrityTerm {
	case state.ToTerm:
		if err := noderole.Verify(documentBytes, sidecar, kr); err != nil {
			return fmt.Errorf("resume rotation authenticate target node-role sidecar: %w", err)
		}
		report.AlreadyTarget++
		return nil
	case state.FromTerm:
		if err := verifyPinnedBytes(sidecarEntry, sidecarBytes); err != nil {
			return fmt.Errorf("resume rotation pinned node-role sidecar: %w", err)
		}
		if err := noderole.Verify(documentBytes, sidecar, kr); err != nil {
			return fmt.Errorf("resume rotation verify pinned node-role sidecar: %w", err)
		}
	default:
		return fmt.Errorf(
			"resume rotation node-role sidecar has unauthorized term %d, want retiring %d or target %d",
			sidecar.IntegrityTerm,
			state.FromTerm,
			state.ToTerm,
		)
	}
	target, err := noderole.Sign(documentBytes, kr, time.Now(), 0)
	if err != nil {
		return fmt.Errorf("resume rotation sign node-role sidecar: %w", err)
	}
	encoded, err := noderole.MarshalSidecar(target)
	if err != nil {
		return fmt.Errorf("resume rotation marshal node-role sidecar: %w", err)
	}
	path, err := resolveResumePath(paths, sidecarEntry.Path)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(path, encoded); err != nil {
		return fmt.Errorf("resume rotation write node-role sidecar: %w", err)
	}
	report.Resigned++
	return nil
}

func readPinnedDocument(paths storepaths.Paths, entry Entry) ([]byte, error) {
	data, err := readResumeEntry(paths, entry, false)
	if err != nil {
		return nil, err
	}
	if err := verifyPinnedBytes(entry, data); err != nil {
		return nil, err
	}
	return data, nil
}

func verifyPinnedEntry(paths storepaths.Paths, entry Entry) error {
	data, err := readResumeEntry(paths, entry, false)
	if err != nil {
		return err
	}
	return verifyPinnedBytes(entry, data)
}

func readResumeEntry(
	paths storepaths.Paths,
	entry Entry,
	allowTargetOutput bool,
) ([]byte, error) {
	path, err := resolveResumePath(paths, entry.Path)
	if err != nil {
		return nil, err
	}
	if err := fsutil.RemoveDurableWriteTemps(path); err != nil {
		return nil, fmt.Errorf(
			"reconcile durable-write residue for %q: %w",
			entry.Path,
			err,
		)
	}
	limit := entry.Size
	if allowTargetOutput {
		if limit > math.MaxInt64-rewrapOutputSizeAllowance {
			return nil, fmt.Errorf("entry %q size cannot be bounded safely", entry.Path)
		}
		limit += rewrapOutputSizeAllowance
	}
	data, _, err := fsutil.ReadRegularFileLimited(path, limit)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func verifyPinnedBytes(entry Entry, data []byte) error {
	if int64(len(data)) != entry.Size {
		return fmt.Errorf(
			"exact size %d does not match snapshot size %d",
			len(data),
			entry.Size,
		)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
		return fmt.Errorf(
			"exact SHA-256 %s does not match snapshot SHA-256 %s",
			got,
			entry.SHA256,
		)
	}
	return nil
}

func resolveResumePath(paths storepaths.Paths, canonical string) (string, error) {
	if err := validateCanonicalPath(canonical); err != nil {
		return "", err
	}
	root, err := filepath.Abs(paths.Root())
	if err != nil {
		return "", err
	}
	resolved, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(canonical)))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("rotation snapshot path escapes signer data root: %q", canonical)
	}
	return resolved, nil
}

func historicalGenerationPrefixes(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
) ([]string, error) {
	anchors := kr.HistoricalGenerationAnchors()
	prefixes := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		relative, err := filepath.Rel(
			paths.Root(),
			paths.GenerationDir(identityID, anchor.GenerationID),
		)
		if err != nil {
			return nil, err
		}
		canonical := filepath.ToSlash(relative)
		if err := validateCanonicalPath(canonical); err != nil {
			return nil, err
		}
		prefixes = append(prefixes, canonical+"/")
	}
	slices.Sort(prefixes)
	return prefixes, nil
}

func hasCanonicalPrefix(path string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(prefix string) bool {
		return strings.HasPrefix(path, prefix)
	})
}

func validateIntegrityPairs(
	paths storepaths.Paths,
	identityID string,
	entries map[ArtifactKind][]Entry,
) error {
	pairs := []struct {
		label        string
		documentKind ArtifactKind
		sidecarKind  ArtifactKind
		documentPath string
		sidecarPath  string
	}{
		{
			label:        "policy",
			documentKind: KindPolicyDocument,
			sidecarKind:  KindPolicySidecar,
			documentPath: policy.PolicyPath(paths.Root(), identityID),
			sidecarPath: policy.PolicyIntegritySidecarPath(
				policy.PolicyPath(paths.Root(), identityID),
			),
		},
		{
			label:        "node role",
			documentKind: KindNodeRoleDocument,
			sidecarKind:  KindNodeRoleSidecar,
			documentPath: paths.NodeRolePath(),
			sidecarPath:  paths.NodeRoleIntegritySidecar(identityID),
		},
	}
	for _, pair := range pairs {
		documents := entries[pair.documentKind]
		sidecars := entries[pair.sidecarKind]
		if len(documents) != 1 || len(sidecars) != 1 {
			return fmt.Errorf(
				"resume rotation requires exactly one %s document and sidecar",
				pair.label,
			)
		}
		documentCanonical, err := canonicalPathFor(paths, pair.documentPath)
		if err != nil {
			return err
		}
		sidecarCanonical, err := canonicalPathFor(paths, pair.sidecarPath)
		if err != nil {
			return err
		}
		if documents[0].Path != documentCanonical ||
			sidecars[0].Path != sidecarCanonical {
			return fmt.Errorf(
				"resume rotation %s paths do not match owned storage paths",
				pair.label,
			)
		}
	}
	return nil
}

func canonicalPathFor(paths storepaths.Paths, absolute string) (string, error) {
	relative, err := filepath.Rel(paths.Root(), absolute)
	if err != nil {
		return "", err
	}
	canonical := filepath.ToSlash(relative)
	if err := validateCanonicalPath(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}
