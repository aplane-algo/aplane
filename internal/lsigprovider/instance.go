// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

// Instance is what one set of creation parameters selects from a provider: the
// contract the resulting account will have. A fixed provider has one instance
// for every set of values. A per-key provider has one for each shape it can
// produce, so its type-level definition cannot answer these questions.
type Instance struct {
	// Parameters are the definitions that apply to this instance.
	Parameters []ParameterDef
	// Values are the canonical creation values.
	Values map[string]string
	// Bounded is the definition-level bounded contract, or nil when the account
	// is not bounded. Fields that need the final program are not populated.
	Bounded *boundedmeta.Metadata
	// Fingerprint is the definition this account records as its provenance.
	Fingerprint string
	// ReviewFingerprint is what an operator approves by reviewing this request.
	// It is Fingerprint unless the type's approval covers more than one
	// definition, as a grammar does.
	ReviewFingerprint string
	// BoundaryDigest compares the resolved policy and external authorities of
	// two accounts. It is empty for a type that does not define one.
	BoundaryDigest string
	// Unavailable says why these parameters select no account the type creates,
	// and is empty when they select one. A plain host's program without
	// overlays is the composition base and the program of restored plain keys,
	// so key generation can derive it, but no account is created as one.
	Unavailable string
}

// InstanceResolver is implemented by providers whose contract varies by key.
// Providers that do not implement it have one fixed contract, and the package
// functions below adapt them.
type InstanceResolver interface {
	// CosignerComponentKeyType reports the component key type of a cosigner the
	// parameters ask for. It runs before references are resolved, so it must not
	// need a resolved cosigner public key.
	CosignerComponentKeyType(params map[string]string) (string, bool)
	// ResolveInstance selects and validates the instance for resolved parameters.
	ResolveInstance(params map[string]string) (*Instance, error)
	// StoredFingerprint returns the current fingerprint of a stored account's
	// definition. It reads only the stored values: resolving an old reference or
	// applying today's defaults could identify a different definition.
	StoredFingerprint(parameters map[string]string, metadata *boundedmeta.Metadata) (string, error)
}

type boundedDefinition interface {
	BoundedAuthorizationMetadata() *boundedmeta.Metadata
}

func fixedBoundedMetadata(provider LSigProvider) *boundedmeta.Metadata {
	if definition, ok := provider.(boundedDefinition); ok {
		return definition.BoundedAuthorizationMetadata()
	}
	return nil
}

// CosignerComponentKeyType reports the component key type of a cosigner that
// params ask for, before any reference is resolved.
func CosignerComponentKeyType(provider LSigProvider, params map[string]string) (string, bool) {
	if resolver, ok := provider.(InstanceResolver); ok {
		return resolver.CosignerComponentKeyType(params)
	}
	metadata := fixedBoundedMetadata(provider)
	if metadata == nil || metadata.Cosigner == nil {
		return "", false
	}
	return metadata.Cosigner.ComponentKeyType, true
}

// ResolveInstance returns the instance params select from provider.
func ResolveInstance(provider LSigProvider, params map[string]string) (*Instance, error) {
	if resolver, ok := provider.(InstanceResolver); ok {
		instance, err := resolver.ResolveInstance(params)
		if err != nil {
			return nil, err
		}
		if instance == nil {
			return nil, fmt.Errorf("%s resolved no instance", provider.KeyType())
		}
		return instance, nil
	}
	definitions := provider.CreationParams()
	values, err := NormalizeCreationParams(params, definitions)
	if err != nil {
		return nil, err
	}
	fingerprint, _ := CompatibilityFingerprintOf(provider)
	return &Instance{
		Parameters:        definitions,
		Values:            values,
		Bounded:           fixedBoundedMetadata(provider),
		Fingerprint:       fingerprint,
		ReviewFingerprint: fingerprint,
	}, nil
}

// CreationFingerprint returns the provenance fingerprint a new account records.
// An unregistered provider or one with no fingerprint records none.
func CreationFingerprint(keyType string, params map[string]string) (string, error) {
	provider := Get(keyType)
	if provider == nil {
		return "", nil
	}
	if _, ok := provider.(InstanceResolver); !ok {
		return TemplateFingerprintForKeyType(keyType), nil
	}
	instance, err := ResolveInstance(provider, params)
	if err != nil {
		return "", fmt.Errorf("resolve creation fingerprint: %w", err)
	}
	return instance.Fingerprint, nil
}

// CompareAccountProvenance compares a stored account's provenance with the
// definition currently registered. A provider whose contract varies by key is
// compared against that account's own definition, so a change to an unrelated
// shape reports nothing.
func CompareAccountProvenance(keyType, storedFingerprint string, parameters map[string]string, metadata *boundedmeta.Metadata) (status, note string) {
	resolver, ok := Get(keyType).(InstanceResolver)
	if !ok {
		return CompareTemplateFingerprint(keyType, storedFingerprint)
	}
	if storedFingerprint == "" {
		return "", ""
	}
	live, err := resolver.StoredFingerprint(parameters, metadata)
	if err != nil {
		return TemplateProvenanceStatusUnavailable, "the definition of this account is not available in this signer"
	}
	return compareFingerprints(storedFingerprint, live)
}
