// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package generictemplate

import (
	"strings"
	"testing"
)

const fingerprintBaseYAML = `
schema_version: 1
template_mode: strict
publisher: test
family: synthetic-generic
version: 1
display_name: "Synthetic Generic"
description: "behavior fingerprint base"
display_color: "35"
parameters:
  - name: owner
    type: address
    required: true
template_variables:
  - name: owner_const
    source: parameter
    parameter: owner
    type: address
    constant: byte
runtime_args:
  - name: preimage
    type: bytes
    required: true
    byte_length: 32
teal: |
  $owner_const
  len
  int 32
  ==
  assert
  int 1
  return
`

func mustGenericFingerprint(t *testing.T, yaml string) string {
	t.Helper()
	got, err := SemanticFingerprint([]byte(yaml))
	if err != nil {
		t.Fatalf("SemanticFingerprint() error = %v", err)
	}
	return got
}

func TestGenericFingerprintCarriesVersionPrefix(t *testing.T) {
	got := mustGenericFingerprint(t, fingerprintBaseYAML)
	if !strings.HasPrefix(got, "1:") {
		t.Fatalf("SemanticFingerprint() = %q, want a \"1:\" prefix", got)
	}
}

// TestGenericFingerprintIdentityRenameStable proves identity/display metadata is
// excluded: changing publisher/family/version/display_name/description/color
// does not change the fingerprint.
func TestGenericFingerprintIdentityRenameStable(t *testing.T) {
	base := mustGenericFingerprint(t, fingerprintBaseYAML)

	renamed := strings.NewReplacer(
		"publisher: test", "publisher: someoneelse",
		"family: synthetic-generic", "family: renamed-family",
		"\nversion: 1\n", "\nversion: 99\n", // only the standalone version line, not schema_version
		`display_name: "Synthetic Generic"`, `display_name: "Renamed Display"`,
		`description: "behavior fingerprint base"`, `description: "totally different text"`,
		`display_color: "35"`, `display_color: "31"`,
	).Replace(fingerprintBaseYAML)

	if got := mustGenericFingerprint(t, renamed); got != base {
		t.Fatalf("identity rename changed the fingerprint: %q != %q", got, base)
	}
}

// TestGenericFingerprintBehaviorSensitive proves behavior-bearing fields change
// the fingerprint.
func TestGenericFingerprintBehaviorSensitive(t *testing.T) {
	base := mustGenericFingerprint(t, fingerprintBaseYAML)

	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "opcode ceiling",
			yaml: strings.Replace(fingerprintBaseYAML,
				"template_mode: strict",
				"template_mode: strict\nmax_opcode_cost: 12345",
				1),
		},
		{
			name: "teal",
			yaml: strings.Replace(fingerprintBaseYAML, "int 32", "int 64", 1),
		},
		{
			name: "parameters",
			yaml: strings.Replace(fingerprintBaseYAML,
				"  - name: owner\n    type: address\n    required: true\n",
				"  - name: owner\n    type: address\n    required: true\n  - name: extra\n    type: uint64\n    required: false\n",
				1),
		},
		{
			name: "runtime_args",
			yaml: strings.Replace(fingerprintBaseYAML,
				"    byte_length: 32",
				"    byte_length: 64",
				1),
		},
		{
			// The base YAML omits derivation_version; adding the one supported
			// contract must still move the fingerprint.
			name: "derivation_version",
			yaml: strings.Replace(fingerprintBaseYAML,
				"schema_version: 1",
				"schema_version: 1\nderivation_version: 3",
				1),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustGenericFingerprint(t, tc.yaml); got == base {
				t.Fatalf("%s did not change the fingerprint", tc.name)
			}
		})
	}
}
