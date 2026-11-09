// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import "slices"

// FixtureSupport is the support a fixture composer claims for itself.
type FixtureSupport struct {
	Cosigner bool
	// RefuseGeneration makes the policy refuse every new account, as a narrowed
	// production policy would for a base it stops supporting.
	RefuseGeneration bool
}

// NewFixtureProvider composes spec on a base that is never registered. The policy
// belongs to the returned composer alone, and production cannot reach this file.
func NewFixtureProvider(spec *TemplateSpec, base BaseRegistration, support FixtureSupport) (*ComposedDSA, error) {
	rules := templateBaseRules{
		registered:     func(baseKeyType string) bool { return baseKeyType == base.BaseKeyType },
		allowsCosigner: func(string) bool { return support.Cosigner },
	}
	if err := validateTemplateSpec(spec, rules); err != nil {
		return nil, err
	}
	provider, err := newProviderFromBase(spec, base, mustTemplateSaltStyle(spec.DerivationVersion))
	if err != nil {
		return nil, err
	}
	provider.generationPolicy = func(_, baseKeyType string) (boundedWorkflowSupport, bool) {
		if baseKeyType != base.BaseKeyType || support.RefuseGeneration {
			return boundedWorkflowSupport{}, false
		}
		return boundedWorkflowSupport{cosigner: support.Cosigner}, true
	}
	return provider, nil
}

// RegisteredBaseKeyTypes lists the bases registered in this process.
func RegisteredBaseKeyTypes() []string {
	baseRegistry.mu.RLock()
	defer baseRegistry.mu.RUnlock()
	keyTypes := make([]string, 0, len(baseRegistry.bases))
	for keyType := range baseRegistry.bases {
		keyTypes = append(keyTypes, keyType)
	}
	slices.Sort(keyTypes)
	return keyTypes
}

// ProductionSupportsBase reports whether a contract's production policy lists a base.
func ProductionSupportsBase(contract, baseKeyType string) bool {
	_, ok := productionBoundedGenerationPolicy(contract, baseKeyType)
	return ok
}

// NarrowCosignerSupport makes provider's generation policy refuse a cosigner on
// its base, as a production policy that stops supporting one would. Every
// production base supports a cosigner, so this is the only way to reach that
// refusal.
func NarrowCosignerSupport(provider *ComposedDSA) {
	provider.generationPolicy = func(contract, baseKeyType string) (boundedWorkflowSupport, bool) {
		support, ok := productionBoundedGenerationPolicy(contract, baseKeyType)
		support.cosigner = false
		return support, ok
	}
}
