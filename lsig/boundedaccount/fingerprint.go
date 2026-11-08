// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// A composed fingerprint hashes configuration, not the code that renders it, so
// a behavior change in Go must be declared here. The goldens fail when output
// changes and make that review unavoidable; nothing proves it automatically.
//
// These are hashed inputs, separate from the fingerprint format version. Keep an
// existing shape's revisions stable when adding an independent rule: a shape's
// revision changes only when that shape's behavior does.
const (
	// grammarRevision covers the boundary grammar as a whole. It reaches only
	// the grammar fingerprint, so no account's provenance depends on it.
	grammarRevision = 2
	// resolverRevision covers how selectShape turns a request into values.
	resolverRevision = 1
	// allowlistRendererRevision covers the framework allowlist renderers and the
	// bounded envelope around them.
	allowlistRendererRevision = 1
	// timelockRendererRevision covers the same for shapes with a timelock. It is
	// separate so a timelock change leaves allowlist accounts' provenance alone.
	timelockRendererRevision = 1

	boundaryDigestDomainV1 = "APLANE_GENERAL_BOUNDARY_V1"
)

// shapeFingerprint is one shape's provenance. It binds that shape alone, so a
// rule added to the grammar leaves existing accounts' provenance unchanged.
func shapeFingerprint(shape Shape, composer *composeddsa.ComposedDSA) string {
	rendererRevision := allowlistRendererRevision
	if shape.Timelock {
		rendererRevision = timelockRendererRevision
	}
	return lsigprovider.HashCompatibilitySpec(struct {
		Descriptor        string `json:"descriptor"`
		Composed          string `json:"composed_fingerprint"`
		ResolverRevision  int    `json:"resolver_revision"`
		RendererRevision  int    `json:"renderer_revision"`
		DefinitionVersion string `json:"definition"`
	}{
		Descriptor:        shape.Descriptor(),
		Composed:          composer.CompatibilityFingerprint(),
		ResolverRevision:  resolverRevision,
		RendererRevision:  rendererRevision,
		DefinitionVersion: composer.KeyType(),
	})
}

// grammarFingerprint identifies the whole grammar, so a review can tell that it
// changed before generation. Shapes are a labelled, ordered mapping: an unlabelled
// bag of hashes could not say which behavior belongs to which request.
func grammarFingerprint(definitions []*shapeDefinition) string {
	type entry struct {
		Descriptor  string `json:"descriptor"`
		Fingerprint string `json:"fingerprint"`
	}
	shapes := make([]entry, len(definitions))
	for i, definition := range definitions {
		shapes[i] = entry{definition.shape.Descriptor(), definition.fingerprint}
	}
	return lsigprovider.HashCompatibilitySpec(struct {
		Schema        string  `json:"schema"`
		Revision      int     `json:"grammar_revision"`
		AutoInlineMax int     `json:"auto_inline_max"`
		InlineMax     int     `json:"inline_max"`
		RecipientsMax int     `json:"recipients_max"`
		Shapes        []entry `json:"shapes"`
	}{BoundarySchemaV1, grammarRevision, AutoInlineMax, InlineMax, RecipientsMax, shapes})
}

// boundaryDigest compares two accounts' resolved policy and external authorities.
// It excludes the spending key, so equal digests do not mean equal accounts, and
// it replaces no signing transcript. A cosigner key is a behavior parameter and is
// covered by the behavior encoding.
func boundaryDigest(definition *shapeDefinition, parameters map[string]string) (string, error) {
	composer := definition.composer
	profile, err := composeddsa.CanonicalBoundedProfile(composer.BoundedAuthorizationProfile(), composer.BoundedAuthorizationMetadata())
	if err != nil {
		return "", fmt.Errorf("encode bounded profile: %w", err)
	}
	behavior, err := composeddsa.CanonicalBoundedBehaviorParameters(parameters, composer.CreationParams())
	if err != nil {
		return "", fmt.Errorf("encode behavior parameters: %w", err)
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundaryDigestDomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(BoundarySchemaV1))
	encoded = boundedmeta.AppendField(encoded, []byte(definition.fingerprint))
	encoded = boundedmeta.AppendField(encoded, []byte(lsigprovider.FingerprintBasePrimitive(composer.BaseKeyType())))
	encoded = boundedmeta.AppendField(encoded, profile)
	encoded = boundedmeta.AppendField(encoded, behavior)
	sum := sha512.Sum512_256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
