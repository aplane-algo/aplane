// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

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

	if got := TemplateFingerprintForKeyType(keyType); got != fpA {
		t.Fatalf("TemplateFingerprintForKeyType() = %q, want %q", got, fpA)
	}
	if status, note := CompareTemplateFingerprint(keyType, fpA); status != "" || note != "" {
		t.Fatalf("CompareTemplateFingerprint(match) = (%q, %q), want empty", status, note)
	}
	status, note := CompareTemplateFingerprint(keyType, fpB)
	if status != TemplateProvenanceStatusConflict {
		t.Fatalf("CompareTemplateFingerprint(conflict) status = %q, want %q", status, TemplateProvenanceStatusConflict)
	}
	if note == "" {
		t.Fatal("CompareTemplateFingerprint(conflict) note is empty")
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

	status, note := CompareTemplateFingerprint(keyType, "2:"+strings.Repeat("a", 64))
	if status != TemplateProvenanceStatusUnavailable {
		t.Fatalf("CompareTemplateFingerprint(cross-version) status = %q, want %q", status, TemplateProvenanceStatusUnavailable)
	}
	if note == "" {
		t.Fatal("CompareTemplateFingerprint(cross-version) note is empty")
	}
}

func TestTemplateFingerprintComparisonUnavailable(t *testing.T) {
	status, note := CompareTemplateFingerprint("missing-fingerprint-test-v1", "semantic-a")
	if status != TemplateProvenanceStatusUnavailable {
		t.Fatalf("CompareTemplateFingerprint(unavailable) status = %q, want %q", status, TemplateProvenanceStatusUnavailable)
	}
	if note == "" {
		t.Fatal("CompareTemplateFingerprint(unavailable) note is empty")
	}
}
