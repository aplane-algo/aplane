// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotationinventory owns the canonical cross-artifact inventory used
// by Phase 3 key-term rotation. It classifies every durable artifact whose
// term authority or exact bytes affect a transition and owns the internal
// guarded start, snapshot-pinned resume, and verified completion boundaries.
// Operator-facing orchestration remains a separate lifecycle step.
package rotationinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
)

// ArtifactKind is the durable semantic class of one inventory entry.
type ArtifactKind string

const (
	KindAccountKey            ArtifactKind = "account-key"
	KindSentryCredential      ArtifactKind = "sentry-credential"
	KindKeyTypeTemplate       ArtifactKind = "keytype-template"
	KindPolicyDocument        ArtifactKind = "policy-document"
	KindPolicySidecar         ArtifactKind = "policy-integrity-sidecar"
	KindNodeRoleDocument      ArtifactKind = "node-role-document"
	KindNodeRoleSidecar       ArtifactKind = "node-role-integrity-sidecar"
	KindKeyTypeState          ArtifactKind = "keytype-state"
	KindWitnessPublicMetadata ArtifactKind = "witness-public-metadata"
	KindGenerationManifest    ArtifactKind = "generation-manifest"
	KindGenerationSeal        ArtifactKind = "generation-seal"
	KindRotationSnapshot      ArtifactKind = "rotation-snapshot"
	KindRotationBaseline      ArtifactKind = "rotation-baseline"
)

// Entry pins one exact regular file and records how rotation must understand
// its authority. Path is slash-separated and relative to the signer data
// root. Term is present only for term envelopes and integrity sidecars.
// ObjectClass and ObjectSelector are present only for term envelopes.
type Entry struct {
	Path           string             `json:"path"`
	Kind           ArtifactKind       `json:"kind"`
	Size           int64              `json:"size"`
	SHA256         string             `json:"sha256"`
	Term           int64              `json:"term,omitempty"`
	ObjectClass    crypto.ObjectClass `json:"object_class,omitempty"`
	ObjectSelector string             `json:"object_selector,omitempty"`
}

// Report is one complete, sorted inventory of the supported durable classes.
type Report struct {
	CurrentGeneration string  `json:"current_generation"`
	Entries           []Entry `json:"entries"`

	// currentManifest and currentInventory are derived from the same exact
	// buffers authenticated into Entries. Security decisions made after a
	// scan must consume these pinned values instead of rereading mutable
	// generation files.
	currentManifest  *genstore.Manifest
	currentInventory []genstore.InventoryEntry
}

// ValidateEntries enforces the canonical snapshot-entry contract.
func ValidateEntries(entries []Entry) error {
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		entry := &entries[i]
		if err := validateCanonicalPath(entry.Path); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if _, ok := seen[entry.Path]; ok {
			return fmt.Errorf("duplicate inventory path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if entry.Size <= 0 {
			return fmt.Errorf("entry %q has non-positive size", entry.Path)
		}
		if err := validateSHA256(entry.SHA256); err != nil {
			return fmt.Errorf("entry %q sha256: %w", entry.Path, err)
		}
		if err := validateAuthorityFields(*entry); err != nil {
			return fmt.Errorf("entry %q: %w", entry.Path, err)
		}
	}
	if !slices.IsSortedFunc(entries, func(a, b Entry) int {
		return strings.Compare(a.Path, b.Path)
	}) {
		return fmt.Errorf("inventory entries are not sorted by canonical path")
	}
	return nil
}

func validateAuthorityFields(entry Entry) error {
	expectedClass, termEnvelope, integritySidecar, ok := kindAuthority(entry.Kind)
	if !ok {
		return fmt.Errorf("unknown artifact kind %q", entry.Kind)
	}
	switch {
	case termEnvelope:
		if entry.Term <= 0 {
			return fmt.Errorf("term envelope requires a positive term")
		}
		if entry.ObjectClass != expectedClass || entry.ObjectSelector == "" {
			return fmt.Errorf(
				"term envelope requires object context %s:<selector>",
				expectedClass,
			)
		}
	case integritySidecar:
		if entry.Term <= 0 {
			return fmt.Errorf("integrity sidecar requires a positive term")
		}
		if entry.ObjectClass != "" || entry.ObjectSelector != "" {
			return fmt.Errorf("integrity sidecar must not carry an envelope context")
		}
	default:
		if entry.Term != 0 || entry.ObjectClass != "" || entry.ObjectSelector != "" {
			return fmt.Errorf("plaintext artifact must not carry term-envelope authority")
		}
	}
	return nil
}

func kindAuthority(kind ArtifactKind) (crypto.ObjectClass, bool, bool, bool) {
	switch kind {
	case KindAccountKey:
		return crypto.ClassAccountKey, true, false, true
	case KindSentryCredential:
		return crypto.ClassSentryCredential, true, false, true
	case KindKeyTypeTemplate:
		return crypto.ClassKeyTypeTemplate, true, false, true
	case KindRotationSnapshot:
		return crypto.ClassRotationSnapshot, true, false, true
	case KindRotationBaseline:
		return crypto.ClassRotationBaseline, true, false, true
	case KindPolicySidecar, KindNodeRoleSidecar:
		return "", false, true, true
	case KindPolicyDocument, KindNodeRoleDocument, KindKeyTypeState,
		KindWitnessPublicMetadata, KindGenerationManifest, KindGenerationSeal:
		return "", false, false, true
	default:
		return "", false, false, false
	}
}

func validateCanonicalPath(value string) error {
	if value == "" || !utf8.ValidString(value) || strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return fmt.Errorf("invalid canonical path %q", value)
	}
	cleaned := path.Clean(value)
	if cleaned != value || cleaned == "." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("invalid canonical path %q", value)
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("invalid canonical path %q", value)
		}
	}
	return nil
}

func validateSHA256(value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("must be %d lowercase hexadecimal characters", sha256.Size*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("must be %d lowercase hexadecimal characters", sha256.Size*2)
	}
	return nil
}
