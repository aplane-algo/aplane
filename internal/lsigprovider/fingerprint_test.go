// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"fmt"
	"strings"
	"testing"
)

func TestProjectParameterDefDropsDisplayFields(t *testing.T) {
	min := uint64(1)
	max := uint64(9)
	got := ProjectParameterDef(ParameterDef{
		Name:        "amount",
		Label:       "Amount",
		Description: "Display-only description",
		Type:        "uint64",
		Required:    true,
		MaxLength:   20,
		InputModes:  []InputMode{{Name: "raw", Label: "Raw"}},
		MinItems:    2,
		MaxItems:    4,
		Example:     "5",
		Placeholder: "Enter amount",
		Min:         &min,
		Max:         &max,
		Default:     "5",
	})

	if got.Name != "amount" || got.Type != "uint64" || !got.Required || got.MaxLength != 20 ||
		got.MinItems != 2 || got.MaxItems != 4 || got.Min == nil || *got.Min != min ||
		got.Max == nil || *got.Max != max || got.Default != "5" {
		t.Fatalf("ProjectParameterDef() = %#v", got)
	}
}

func TestProjectRuntimeArgDefDropsDisplayFields(t *testing.T) {
	got := ProjectRuntimeArgDef(RuntimeArgDef{
		Name:        "preimage",
		Label:       "Preimage",
		Description: "Display-only description",
		Type:        "bytes",
		Required:    true,
		ByteLength:  32,
	})

	if got.Name != "preimage" || got.Type != "bytes" || !got.Required || got.ByteLength != 32 {
		t.Fatalf("ProjectRuntimeArgDef() = %#v", got)
	}
}

func TestHashCompatibilitySpecPanicsOnInvalidSpec(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("HashCompatibilitySpec() did not panic for an unmarshable canonical spec")
		}
	}()

	HashCompatibilitySpec(struct {
		Bad func() `json:"bad"`
	}{})
}

// TestHashCompatibilitySpecCarriesVersionPrefix pins the versioned wire format:
// every emitted fingerprint is "<version>:<hex>".
func TestHashCompatibilitySpecCarriesVersionPrefix(t *testing.T) {
	got := HashCompatibilitySpec(struct {
		A string `json:"a"`
	}{A: "x"})

	wantPrefix := fmt.Sprintf("%d:", CompatibilityFingerprintVersion)
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("HashCompatibilitySpec() = %q, want prefix %q", got, wantPrefix)
	}
	parsed, ok := ParseCompatibilityFingerprint(got)
	if !ok {
		t.Fatalf("ParseCompatibilityFingerprint(%q) ok = false, want true", got)
	}
	if parsed.Version != CompatibilityFingerprintVersion {
		t.Fatalf("parsed version = %d, want %d", parsed.Version, CompatibilityFingerprintVersion)
	}
	if len(parsed.Hash) != 64 {
		t.Fatalf("parsed hash = %q (len %d), want a 64-char sha256 hex", parsed.Hash, len(parsed.Hash))
	}
}

func TestParseCompatibilityFingerprint(t *testing.T) {
	hexA := strings.Repeat("a", 64)
	hexB := strings.Repeat("b", 64)
	tests := []struct {
		in          string
		wantVersion int
		wantHash    string
		wantOK      bool
	}{
		{in: "1:" + hexA, wantVersion: 1, wantHash: hexA, wantOK: true},
		{in: "2:" + hexA, wantVersion: 2, wantHash: hexA, wantOK: true},
		{in: "10:" + hexB, wantVersion: 10, wantHash: hexB, wantOK: true},
		{in: "abcd", wantVersion: 0, wantHash: "abcd", wantOK: false},
		{in: "", wantVersion: 0, wantHash: "", wantOK: false},
		{in: "x:" + hexA, wantVersion: 0, wantHash: "x:" + hexA, wantOK: false},
		{in: "0:" + hexA, wantVersion: 0, wantHash: "0:" + hexA, wantOK: false},
		{in: ":" + hexA, wantVersion: 0, wantHash: ":" + hexA, wantOK: false},
		{in: "-1:" + hexA, wantVersion: 0, wantHash: "-1:" + hexA, wantOK: false},
		// valid version prefix but malformed (non-sha256-hex) hash -> not comparable
		{in: "1:not-a-sha256", wantVersion: 1, wantHash: "not-a-sha256", wantOK: false},
		{in: "1:" + hexA[:63], wantVersion: 1, wantHash: hexA[:63], wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParseCompatibilityFingerprint(tc.in)
			if ok != tc.wantOK || got.Version != tc.wantVersion || got.Hash != tc.wantHash {
				t.Fatalf("ParseCompatibilityFingerprint(%q) = (%+v, %v), want ({%d %q}, %v)",
					tc.in, got, ok, tc.wantVersion, tc.wantHash, tc.wantOK)
			}
		})
	}
}

func TestFingerprintsMatch(t *testing.T) {
	hexA := strings.Repeat("a", 64)
	hexB := strings.Repeat("b", 64)
	tests := []struct {
		name           string
		stored         string
		live           string
		wantMatch      bool
		wantComparable bool
	}{
		{name: "same version same hash", stored: "1:" + hexA, live: "1:" + hexA, wantMatch: true, wantComparable: true},
		{name: "same version different hash", stored: "1:" + hexA, live: "1:" + hexB, wantMatch: false, wantComparable: true},
		{name: "different versions not comparable", stored: "1:" + hexA, live: "2:" + hexA, wantMatch: false, wantComparable: false},
		{name: "empty stored not comparable", stored: "", live: "1:" + hexA, wantMatch: false, wantComparable: false},
		{name: "empty live not comparable", stored: "1:" + hexA, live: "", wantMatch: false, wantComparable: false},
		{name: "unparseable stored not comparable", stored: "aaaa", live: "1:" + hexA, wantMatch: false, wantComparable: false},
		{name: "unparseable live not comparable", stored: "1:" + hexA, live: "aaaa", wantMatch: false, wantComparable: false},
		{name: "both unparseable not comparable", stored: "aaaa", live: "aaaa", wantMatch: false, wantComparable: false},
		{name: "malformed stored not comparable", stored: "1:not-a-sha256", live: "1:" + hexA, wantMatch: false, wantComparable: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, comparable := FingerprintsMatch(tc.stored, tc.live)
			if match != tc.wantMatch || comparable != tc.wantComparable {
				t.Fatalf("FingerprintsMatch(%q, %q) = (%v, %v), want (%v, %v)",
					tc.stored, tc.live, match, comparable, tc.wantMatch, tc.wantComparable)
			}
		})
	}
}

// TestFingerprintBasePrimitiveFrozenMap pins the frozen base→token namespace.
// A failure here means a token was renamed — which would silently re-conflict
// every key in the field. Add rows, never rename tokens.
func TestFingerprintBasePrimitiveFrozenMap(t *testing.T) {
	frozen := map[string]string{
		"aplane.falcon1024.v1":         "falcon1024-v1",
		"aplane.ed25519.v1":            "ed25519-lsig-v1",
		"aplane.ed25519lsig.v1":        "ed25519-lsig-v1",
		"aplane.ecdsak1.v1":            "ecdsak1-v1",
		"aplane.falcon1024_ed25519.v1": "falcon1024-ed25519-v1",
	}
	for raw, want := range frozen {
		if got := FingerprintBasePrimitive(raw); got != want {
			t.Fatalf("FingerprintBasePrimitive(%q) = %q, want %q (frozen namespace)", raw, got, want)
		}
	}
	// Pre-rename and current Ed25519 LogicSig base names share one token, so a
	// base-identifier rename never changes the fingerprint.
	if FingerprintBasePrimitive("aplane.ed25519lsig.v1") != FingerprintBasePrimitive("aplane.ed25519.v1") {
		t.Fatal("aplane.ed25519lsig.v1 and aplane.ed25519.v1 must project to the same token")
	}
	// Built-in spelling variants (case/whitespace) normalize to the token.
	if got := FingerprintBasePrimitive("  APLANE.FALCON1024.V1  "); got != "falcon1024-v1" {
		t.Fatalf("built-in spelling variant = %q, want %q", got, "falcon1024-v1")
	}
}

// TestFingerprintBasePrimitiveFallbackNormalizes pins the rename-stability
// mechanism for non-built-in bases: spelling variants (case/whitespace) of an
// unknown base collapse to a single normalized token, so two raw base spellings
// that mean the same primitive fingerprint identically. (For built-in bases the
// same stability is achieved by adding a new raw->token row pointing at the
// existing token.)
func TestFingerprintBasePrimitiveFallbackNormalizes(t *testing.T) {
	a := FingerprintBasePrimitive("custom.base.v1")
	b := FingerprintBasePrimitive("  CUSTOM.BASE.V1  ")
	if a != "custom.base.v1" || a != b {
		t.Fatalf("FingerprintBasePrimitive fallback normalization = (%q, %q), want both %q", a, b, "custom.base.v1")
	}
}
