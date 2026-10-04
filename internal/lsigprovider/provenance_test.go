// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider_test

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

type fingerprintTestProvider struct {
	keyType     string
	fingerprint string
}

func (p fingerprintTestProvider) KeyType() string                                { return p.keyType }
func (p fingerprintTestProvider) RoutingFamily() string                          { return "fingerprint-test" }
func (p fingerprintTestProvider) Version() int                                   { return 1 }
func (p fingerprintTestProvider) Category() string                               { return lsigprovider.CategoryGenericLsig }
func (p fingerprintTestProvider) DisplayName() string                            { return "Fingerprint Test" }
func (p fingerprintTestProvider) Description() string                            { return "test provider" }
func (p fingerprintTestProvider) DisplayColor() string                           { return "33" }
func (p fingerprintTestProvider) CreationParams() []lsigprovider.ParameterDef    { return nil }
func (p fingerprintTestProvider) ValidateCreationParams(map[string]string) error { return nil }
func (p fingerprintTestProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (p fingerprintTestProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (p fingerprintTestProvider) CompatibilityFingerprint() string { return p.fingerprint }

func TestTemplateFingerprintComparison(t *testing.T) {
	keyType := "fingerprint-test-v1"
	fpA := "1:" + strings.Repeat("a", 64)
	fpB := "1:" + strings.Repeat("b", 64)
	lsigprovider.Register(fingerprintTestProvider{keyType: keyType, fingerprint: fpA})
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })

	if got := lsigprovider.TemplateFingerprintForKeyType(keyType); got != fpA {
		t.Fatalf("lsigprovider.TemplateFingerprintForKeyType() = %q, want %q", got, fpA)
	}
	if status, note := lsigprovider.CompareTemplateFingerprint(keyType, fpA); status != "" || note != "" {
		t.Fatalf("lsigprovider.CompareTemplateFingerprint(match) = (%q, %q), want empty", status, note)
	}
	status, note := lsigprovider.CompareTemplateFingerprint(keyType, fpB)
	if status != lsigprovider.TemplateProvenanceStatusConflict {
		t.Fatalf("lsigprovider.CompareTemplateFingerprint(conflict) status = %q, want %q", status, lsigprovider.TemplateProvenanceStatusConflict)
	}
	if note == "" {
		t.Fatal("lsigprovider.CompareTemplateFingerprint(conflict) note is empty")
	}
}

// TestTemplateFingerprintCrossVersionIsBenign pins the forward-format guard:
// a stored fingerprint from a different (future) formula version must read as
// unavailable, never as a conflict, so a formula bump cannot false-flag keys.
func TestTemplateFingerprintCrossVersionIsBenign(t *testing.T) {
	keyType := "fingerprint-test-crossversion-v1"
	fpA := "1:" + strings.Repeat("a", 64)
	lsigprovider.Register(fingerprintTestProvider{keyType: keyType, fingerprint: fpA})
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })

	status, note := lsigprovider.CompareTemplateFingerprint(keyType, "2:"+strings.Repeat("a", 64))
	if status != lsigprovider.TemplateProvenanceStatusUnavailable {
		t.Fatalf("lsigprovider.CompareTemplateFingerprint(cross-version) status = %q, want %q", status, lsigprovider.TemplateProvenanceStatusUnavailable)
	}
	if note == "" {
		t.Fatal("lsigprovider.CompareTemplateFingerprint(cross-version) note is empty")
	}
}

func TestTemplateFingerprintComparisonUnavailable(t *testing.T) {
	status, note := lsigprovider.CompareTemplateFingerprint("missing-fingerprint-test-v1", "semantic-a")
	if status != lsigprovider.TemplateProvenanceStatusUnavailable {
		t.Fatalf("lsigprovider.CompareTemplateFingerprint(unavailable) status = %q, want %q", status, lsigprovider.TemplateProvenanceStatusUnavailable)
	}
	if note == "" {
		t.Fatal("lsigprovider.CompareTemplateFingerprint(unavailable) note is empty")
	}
}
