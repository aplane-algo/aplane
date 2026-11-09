// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// noneTemplateYAML is the composition the general type builds in Go for a
// limits-only shape. A template file can't declare it; the composer tests parse it
// with the generic parser to reach the composer's own checks.
const noneTemplateYAML = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: limits-only
version: 1
display_name: "Limits Only"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: spending_key
  layer3:
    policy: none
`

func noneComposer(yaml string) (*composeddsa.ComposedDSA, error) {
	falcon1024.RegisterClient()
	spec, err := generictemplate.ParseTemplateSpec([]byte(yaml))
	if err != nil {
		return nil, err
	}
	return composeddsa.NewProviderFromTemplateSpec(spec)
}

func TestNonePolicyRendersNoLayer3(t *testing.T) {
	provider, err := noneComposer(noneTemplateYAML)
	if err != nil {
		t.Fatal(err)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Layer3Policy != boundedmeta.Layer3PolicyNone {
		t.Fatalf("metadata = %#v", metadata)
	}
	if len(provider.CreationParams()) != 0 {
		t.Fatalf("a none policy declares parameters %v", provider.CreationParams())
	}
	teal, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(teal, "__aplane_bounded1_spend:\n// === no framework Layer 3") {
		t.Fatalf("spend does not fall straight through:\n%s", teal)
	}
	if !strings.Contains(teal, "txn Fee\npushint 10000\n<=\nassert\n") {
		t.Fatal("program has no fee ceiling")
	}
}

func TestNonePolicyComposerRejections(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(noneTemplateYAML, old) {
			t.Fatalf("template does not contain %q", old)
		}
		return strings.Replace(noneTemplateYAML, old, new, 1)
	}
	for _, test := range []struct{ name, yaml, want string }{
		{"author TEAL would be custom", noneTemplateYAML + "\ntemplate_variables: []\n\nteal: |\n  txn Fee\n  pop\n", "does not accept author TEAL"},
		{"no recipients parameter", replace("    policy: none\n", "    policy: none\n    recipients_parameter: recipients\n") +
			"\nparameters:\n  - name: recipients\n    type: address[]\n    required: true\n    min_items: 1\n    max_items: 3\n", "does not use recipients_parameter"},
		{"no unlock round parameter", replace("    policy: none\n", "    policy: none\n    unlock_round_parameter: unlock_round\n") +
			"\nparameters:\n  - name: unlock_round\n    type: uint64\n    required: true\n    min: 1\n", "does not use unlock_round_parameter"},
		{"no unused parameter", noneTemplateYAML + "\nparameters:\n  - name: extra\n    type: uint64\n    required: true\n", "is not used by framework policy"},
		{"no runtime argument", replace("  layer3:\n", "  runtime_args:\n    - name: extra\n      type: bytes\n      max_size: 8\n      required_on: [spend]\n  layer3:\n"), "has no author TEAL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, err := noneComposer(test.yaml)
			if err == nil {
				_, err = provider.GenerateTEAL(bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize),
					map[string]string{"recipients": "", "unlock_round": "5", "extra": "1"})
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	if composeddsa.Layer3PolicyNone != boundedmeta.Layer3PolicyNone {
		t.Fatal("generation and storage disagree on the policy name")
	}
}

// Only the general type offers a limits-only account: every route by which a
// template file reaches the composer refuses the policy.
func TestNonePolicyIsRefusedInTemplateFiles(t *testing.T) {
	const want = "offered only by the plain hosts' bounds"
	if _, err := composeddsa.ParseTemplateSpec([]byte(noneTemplateYAML)); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("ParseTemplateSpec error = %v, want %q", err, want)
	}
	if _, err := composeddsa.SemanticFingerprint([]byte(noneTemplateYAML)); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SemanticFingerprint error = %v, want %q", err, want)
	}
	if _, err := composeddsa.PrepareKeystoreTemplateRegistration("test.limits-only.v1", []byte(noneTemplateYAML)); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PrepareKeystoreTemplateRegistration error = %v, want %q", err, want)
	}
}
