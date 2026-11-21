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

func TestTemplateFingerprintComparisonUnavailable(t *testing.T) {
	status, note := lsigprovider.CompareTemplateFingerprint("missing-fingerprint-test-v1", "semantic-a")
	if status != lsigprovider.TemplateProvenanceStatusUnavailable {
		t.Fatalf("lsigprovider.CompareTemplateFingerprint(unavailable) status = %q, want %q", status, lsigprovider.TemplateProvenanceStatusUnavailable)
	}
	if note == "" {
		t.Fatal("lsigprovider.CompareTemplateFingerprint(unavailable) note is empty")
	}
}

// A key's recorded provenance agrees with the registered definition only when
// it is that definition's fingerprint byte for byte; nothing recorded reports
// nothing. Any other value is a conflict, for a provider with one fixed
// contract and for one whose contract varies by key.
func TestTemplateFingerprintComparisonOfARecordedValue(t *testing.T) {
	const (
		fixedKeyType  = "fingerprint-test-recorded-v1"
		perKeyKeyType = "fingerprint-test-recorded-per-key-v1"
		conflictNote  = "creation template fingerprint differs from the currently registered definition"
	)
	live := "1:" + strings.Repeat("a", 64)
	hash := strings.Repeat("a", 64)
	registerForTest(t, fingerprintTestProvider{keyType: fixedKeyType, fingerprint: live})
	registerForTest(t, perKeyProvider{
		fingerprintTestProvider: fingerprintTestProvider{keyType: perKeyKeyType, fingerprint: instanceFingerprintC},
		shapes:                  map[string]string{"list": live},
	})

	for _, test := range []struct {
		name, stored, wantStatus, wantNote string
	}{
		{name: "matching", stored: live},
		{name: "nothing recorded"},
		{name: "mismatching", stored: "1:" + strings.Repeat("b", 64), wantStatus: lsigprovider.TemplateProvenanceStatusConflict, wantNote: conflictNote},
		{name: "unversioned", stored: hash, wantStatus: lsigprovider.TemplateProvenanceStatusConflict, wantNote: conflictNote},
		{name: "version 0", stored: "0:" + hash, wantStatus: lsigprovider.TemplateProvenanceStatusConflict, wantNote: conflictNote},
		{name: "noncanonical prefix", stored: "01:" + hash, wantStatus: lsigprovider.TemplateProvenanceStatusConflict, wantNote: conflictNote},
		{name: "cross-version", stored: "2:" + hash, wantStatus: lsigprovider.TemplateProvenanceStatusConflict, wantNote: conflictNote},
		{name: "malformed hash", stored: "1:" + hash[:63], wantStatus: lsigprovider.TemplateProvenanceStatusConflict, wantNote: conflictNote},
	} {
		t.Run(test.name, func(t *testing.T) {
			if status, note := lsigprovider.CompareTemplateFingerprint(fixedKeyType, test.stored); status != test.wantStatus || note != test.wantNote {
				t.Fatalf("CompareTemplateFingerprint() = (%q, %q), want (%q, %q)", status, note, test.wantStatus, test.wantNote)
			}
			if status, note := lsigprovider.CompareAccountProvenance(perKeyKeyType, test.stored, map[string]string{"shape": "list"}, nil); status != test.wantStatus || note != test.wantNote {
				t.Fatalf("CompareAccountProvenance() = (%q, %q), want (%q, %q)", status, note, test.wantStatus, test.wantNote)
			}
		})
	}
}
