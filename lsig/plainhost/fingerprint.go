// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// A composed fingerprint hashes configuration, not the code that renders it, so
// a behavior change in Go must be declared here, as the general type does. The
// goldens fail when output changes and make that review unavoidable.
const (
	// SchemaV1 names the plain host's request grammar.
	SchemaV1 = "aplane.plain-host.v1"
	// grammarRevision reaches only the grammar fingerprint.
	grammarRevision = 1
	// resolverRevision covers how resolve turns a request into values.
	resolverRevision = 1
	// rendererRevision covers the plain1 program around the overlays.
	rendererRevision = 1

	boundaryDigestDomainV1 = "APLANE_PLAIN_BOUNDARY_V1"
)

// descriptor names an arrangement in fingerprints: always cosigned.
func descriptor(rekey string) string {
	return "cosigner/" + ParameterRekeyAuthority + "=" + rekey
}

// arrangementFingerprint is one arrangement's provenance, binding it alone.
func arrangementFingerprint(rekey string, composer *composeddsa.ComposedDSA) string {
	return lsigprovider.HashCompatibilitySpec(struct {
		Schema           string `json:"schema"`
		Arrangement      string `json:"arrangement"`
		Composed         string `json:"composed_fingerprint"`
		ResolverRevision int    `json:"resolver_revision"`
		RendererRevision int    `json:"renderer_revision"`
		Definition       string `json:"definition"`
	}{SchemaV1, descriptor(rekey), composer.CompatibilityFingerprint(), resolverRevision, rendererRevision, composer.KeyType()})
}

// grammarFingerprint identifies every arrangement a key type offers, in order,
// so a review can tell that it changed before generation.
func grammarFingerprint(keyType string, arrangements []*arrangement) string {
	type entry struct {
		Arrangement string `json:"arrangement"`
		Fingerprint string `json:"fingerprint"`
	}
	entries := make([]entry, len(arrangements))
	for i, selected := range arrangements {
		entries[i] = entry{descriptor(selected.rekey), selected.fingerprint}
	}
	return lsigprovider.HashCompatibilitySpec(struct {
		Schema       string  `json:"schema"`
		Revision     int     `json:"grammar_revision"`
		KeyType      string  `json:"key_type"`
		Arrangements []entry `json:"arrangements"`
	}{SchemaV1, grammarRevision, keyType, entries})
}

// boundaryDigest compares two accounts' resolved contract and external
// authorities, the cosigner and the rekey-to list. It excludes the spending
// key, so equal digests do not mean equal accounts.
func boundaryDigest(selected *arrangement, parameters map[string]string) (string, error) {
	composer := selected.composer
	profile, err := composeddsa.CanonicalBoundedProfile(composer.BoundedAuthorizationProfile(), composer.BoundedAuthorizationMetadata())
	if err != nil {
		return "", fmt.Errorf("encode plain host profile: %w", err)
	}
	behavior, err := composeddsa.CanonicalBoundedBehaviorParameters(parameters, composer.CreationParams())
	if err != nil {
		return "", fmt.Errorf("encode behavior parameters: %w", err)
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundaryDigestDomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(SchemaV1))
	encoded = boundedmeta.AppendField(encoded, []byte(selected.fingerprint))
	encoded = boundedmeta.AppendField(encoded, []byte(lsigprovider.FingerprintBasePrimitive(composer.BaseKeyType())))
	encoded = boundedmeta.AppendField(encoded, profile)
	encoded = boundedmeta.AppendField(encoded, behavior)
	sum := sha512.Sum512_256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
