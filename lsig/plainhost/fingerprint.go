// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// A composed fingerprint hashes configuration, not the code that renders it, so
// a behavior change in Go must be declared here. The goldens fail when output
// changes and make that review unavoidable; nothing proves it automatically.
//
// These are hashed inputs, separate from the fingerprint format version. Keep an
// existing program's revisions stable when adding an independent rule: a
// program's revision changes only when that program's behavior does.
const (
	// grammarRevision covers the host's grammar as a whole: 1 was the plain1
	// arrangements alone, 2 adds the bounded shapes. It reaches only the
	// grammar fingerprint, so no account's provenance depends on it.
	grammarRevision = 2
	// arrangementResolverRevision covers how resolve turns an overlays request
	// into values.
	arrangementResolverRevision = 1
	// arrangementRendererRevision covers the plain1 program around the overlays.
	arrangementRendererRevision = 1
	// shapeResolverRevision covers how selectShape turns a bounds request into
	// values. 1 was the general bounded type's; 2 accepts every combination.
	shapeResolverRevision = 2
	// allowlistRendererRevision covers the framework allowlist renderers and the
	// bounded envelope around them.
	allowlistRendererRevision = 1
	// timelockRendererRevision covers the same for shapes with a timelock. It is
	// separate so a timelock change leaves allowlist accounts' provenance alone.
	timelockRendererRevision = 1
	// limitsRendererRevision covers the envelope alone, for limits-only shapes.
	limitsRendererRevision = 1
	// listRendererRevision covers the listed-rekey path, for shapes and
	// arrangements with a rekey-to list. Only those hash it, so a change to it
	// leaves every account without a list alone.
	listRendererRevision = 1

	boundaryDigestDomainV1 = "APLANE_HOST_BOUNDARY_V1"
)

// descriptor names an arrangement in fingerprints.
func descriptor(selected Arrangement) string {
	name := ParameterRekeyAuthority + "=" + selected.Rekey
	if selected.Cosigner {
		name = "cosigner/" + name
	}
	return name
}

// arrangementFingerprint is one arrangement's provenance, binding it alone.
func arrangementFingerprint(selected Arrangement, composer *composeddsa.ComposedDSA) string {
	// Omitted for an arrangement without a list, as for shapes.
	listRevision := 0
	if selected.HasRekeyList() {
		listRevision = listRendererRevision
	}
	return lsigprovider.HashCompatibilitySpec(struct {
		Schema               string `json:"schema"`
		Arrangement          string `json:"arrangement"`
		Composed             string `json:"composed_fingerprint"`
		ResolverRevision     int    `json:"resolver_revision"`
		RendererRevision     int    `json:"renderer_revision"`
		ListRendererRevision int    `json:"list_renderer_revision,omitempty"`
		Definition           string `json:"definition"`
	}{
		Schema:               boundary.SchemaV1,
		Arrangement:          descriptor(selected),
		Composed:             composer.CompatibilityFingerprint(),
		ResolverRevision:     arrangementResolverRevision,
		RendererRevision:     arrangementRendererRevision,
		ListRendererRevision: listRevision,
		Definition:           composer.KeyType(),
	})
}

// shapeFingerprint is one shape's provenance. It binds that shape alone, so a
// rule added to the grammar leaves existing accounts' provenance unchanged.
func shapeFingerprint(shape Shape, composer *composeddsa.ComposedDSA) string {
	rendererRevision := allowlistRendererRevision
	switch {
	case shape.AnyRecipient:
		rendererRevision = limitsRendererRevision
	case shape.Timelock:
		rendererRevision = timelockRendererRevision
	}
	// Omitted for a shape without a list, so their fingerprints don't carry it.
	listRevision := 0
	if shape.HasRekeyList() {
		listRevision = listRendererRevision
	}
	return lsigprovider.HashCompatibilitySpec(struct {
		Schema               string `json:"schema"`
		Descriptor           string `json:"descriptor"`
		Composed             string `json:"composed_fingerprint"`
		ResolverRevision     int    `json:"resolver_revision"`
		RendererRevision     int    `json:"renderer_revision"`
		ListRendererRevision int    `json:"list_renderer_revision,omitempty"`
		Definition           string `json:"definition"`
	}{
		Schema:               boundary.SchemaV1,
		Descriptor:           shape.Descriptor(),
		Composed:             composer.CompatibilityFingerprint(),
		ResolverRevision:     shapeResolverRevision,
		RendererRevision:     rendererRevision,
		ListRendererRevision: listRevision,
		Definition:           composer.KeyType(),
	})
}

// grammarFingerprint identifies every arrangement and shape a key type offers,
// in order, so a review can tell that it changed before generation. They are a
// labelled, ordered mapping: an unlabelled bag of hashes could not say which
// behavior belongs to which request.
func grammarFingerprint(keyType string, programs []*program) string {
	type entry struct {
		Descriptor  string `json:"descriptor"`
		Fingerprint string `json:"fingerprint"`
	}
	entries := make([]entry, len(programs))
	for i, selected := range programs {
		entries[i] = entry{selected.descriptor, selected.fingerprint}
	}
	return lsigprovider.HashCompatibilitySpec(struct {
		Schema        string  `json:"schema"`
		Revision      int     `json:"grammar_revision"`
		KeyType       string  `json:"key_type"`
		AutoInlineMax int     `json:"auto_inline_max"`
		InlineMax     int     `json:"inline_max"`
		RecipientsMax int     `json:"recipients_max"`
		Programs      []entry `json:"programs"`
	}{boundary.SchemaV1, grammarRevision, keyType, AutoInlineMax, InlineMax, RecipientsMax, entries})
}

// boundaryDigest compares two accounts' resolved contract, bounds and external
// authorities (the cosigner and the rekey-to list, when it has them). It excludes
// the spending key, so equal digests do not mean equal accounts, and it replaces
// no signing transcript.
func boundaryDigest(selected *program, parameters map[string]string) (string, error) {
	composer := selected.composer
	profile, err := composeddsa.CanonicalBoundedProfile(composer.BoundedAuthorizationProfile(), composer.BoundedAuthorizationMetadata())
	if err != nil {
		return "", fmt.Errorf("encode profile: %w", err)
	}
	behavior, err := composeddsa.CanonicalBoundedBehaviorParameters(parameters, composer.CreationParams())
	if err != nil {
		return "", fmt.Errorf("encode behavior parameters: %w", err)
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundaryDigestDomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(boundary.SchemaV1))
	encoded = boundedmeta.AppendField(encoded, []byte(selected.fingerprint))
	encoded = boundedmeta.AppendField(encoded, []byte(lsigprovider.FingerprintBasePrimitive(composer.BaseKeyType())))
	encoded = boundedmeta.AppendField(encoded, profile)
	encoded = boundedmeta.AppendField(encoded, behavior)
	sum := sha512.Sum512_256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
