// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	authorFixedProfileHex  = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000008626f756e6465643200000003000000037061790000000561786665720000000c61737365745f6f70745f696e00000000000027100000000c7370656e64696e675f6b657900000000000000000000001666697865645f616c6c6f776c6973745f637573746f6d000000010000058f000000000000000100000008707265696d616765000000056279746573000000010000000000000040000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f0000000872657175697265640000000872657175697265640000000872657175697265640000000100000008707265696d6167650000000772756e74696d650000004000000008726571756972656400000009666f7262696464656e00000009666f7262696464656e"
	authorMerkleProfileHex = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000008626f756e6465643200000003000000037061790000000561786665720000000c61737365745f6f70745f696e00000000000027100000000c7370656e64696e675f6b65790000000000000000000000176d65726b6c655f616c6c6f776c6973745f637573746f6d000000010000058f000000010000000c6d65726b6c655f70726f6f66000000166d65726b6c655f616c6c6f776c6973745f70726f6f660000000a726563697069656e7473000002000000000100000008707265696d616765000000056279746573000000010000000000000040000000030000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564000000010000000c6d65726b6c655f70726f6f66000000076465726976656400000200000000086f7074696f6e616c00000009666f7262696464656e00000009666f7262696464656e0000000200000008707265696d6167650000000772756e74696d650000004000000008726571756972656400000009666f7262696464656e00000009666f7262696464656e"
)

type authorAllowlistCase struct {
	name       string
	policy     string
	stored     string
	maxItems   int
	derived    string
	preimageAt int
	profileHex string
	length     int
	slots      []string
}

var authorAllowlistCases = []authorAllowlistCase{
	{
		name:       "fixed",
		policy:     composeddsa.Layer3PolicyFixedAllowlist,
		stored:     boundedmeta.Layer3PolicyFixedAllowlistCustom,
		maxItems:   composeddsa.BoundedInlineListMax,
		preimageAt: 1,
		profileHex: authorFixedProfileHex,
		length:     339,
		slots: []string{
			"|0|base_signature_0|base_signature|1423|required|required|",
			"|1|preimage|runtime|64|required|forbidden|",
		},
	},
	{
		name:     "merkle",
		policy:   composeddsa.Layer3PolicyMerkleAllowlist,
		stored:   boundedmeta.Layer3PolicyMerkleAllowlistCustom,
		maxItems: 65536,
		derived: `
  derived_args:
    - name: merkle_proof
      kind: merkle_allowlist_proof
      parameter: recipients
      max_size: 512`,
		preimageAt: 2,
		profileHex: authorMerkleProfileHex,
		length:     473,
		slots: []string{
			"|0|base_signature_0|base_signature|1423|required|required|",
			"|1|merkle_proof|derived|512|optional|forbidden|",
			"|2|preimage|runtime|64|required|forbidden|",
		},
	},
}

// authorAllowlistYAML is an allowlist plus a preimage rule, with a spending-key
// rekey. A rekey never reaches Layer 3, so the vector covers a runtime argument
// required on spend and forbidden on the rekey path.
func authorAllowlistYAML(test authorAllowlistCase) string {
	return fmt.Sprintf(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: author-allowlist-%s
version: 1
display_name: "Author Allowlist"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: spending_key
  layer3:
    policy: %s
    recipients_parameter: recipients%s
  runtime_args:
    - name: preimage
      type: bytes
      max_size: 64
      required_on: [spend]

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: %d
  - name: hash
    type: bytes
    required: true
    max_length: 64

template_variables:
  - name: hash
    source: parameter
    parameter: hash
    type: bytes
    constant: byte

teal: |
  arg %d
  sha256
  $hash
  ==
  assert
`, test.name, test.policy, test.derived, test.maxItems, test.preimageAt)
}

func authorAllowlistProvider(t *testing.T, yaml string) *composeddsa.ComposedDSA {
	t.Helper()
	falcon1024.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	return provider
}

func authorAllowlistParams(extra map[string]string) map[string]string {
	params := map[string]string{
		"recipients": types.Address{1}.String(),
		"hash":       strings.Repeat("ab", 32),
	}
	for name, value := range extra {
		params[name] = value
	}
	return params
}

// These bytes were computed from the canonical encoding in ARCH_BOUNDED_DSA.md by
// a separate encoder, not captured from this package's output.
func TestAllowlistWithAuthorTEALGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("../../docs/ARCH_BOUNDED_DSA.md")
	if err != nil {
		t.Fatalf("read ARCH_BOUNDED_DSA.md: %v", err)
	}
	doc := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "", "`", "").Replace(string(data))
	rows := documentedSlotRows(string(data))
	for _, test := range authorAllowlistCases {
		t.Run(test.name, func(t *testing.T) {
			provider := authorAllowlistProvider(t, authorAllowlistYAML(test))
			metadata := provider.BoundedAuthorizationMetadata()
			if metadata == nil || metadata.Layer3Policy != test.stored {
				t.Fatalf("metadata = %#v, want layer3_policy %q", metadata, test.stored)
			}
			encoded, err := composeddsa.CanonicalBoundedProfile(provider.BoundedAuthorizationProfile(), metadata)
			if err != nil {
				t.Fatalf("CanonicalBoundedProfile() error = %v", err)
			}
			if got := hex.EncodeToString(encoded); got != test.profileHex {
				t.Fatalf("canonical profile = %s, want %s", got, test.profileHex)
			}
			if len(encoded) != test.length {
				t.Fatalf("canonical profile length = %d, want %d", len(encoded), test.length)
			}
			for label, value := range map[string]string{
				"author_" + test.name + "_canonical_bounded_profile_length": fmt.Sprint(test.length),
				"author_" + test.name + "_canonical_bounded_profile_hex":    test.profileHex,
			} {
				if !strings.Contains(doc, label+":"+value) {
					t.Errorf("ARCH_BOUNDED_DSA.md does not document %s %q", label, value)
				}
			}
			for _, row := range test.slots {
				if !rows[row] {
					t.Errorf("ARCH_BOUNDED_DSA.md does not document slot row %q", row)
				}
			}
		})
	}
}

// documentedSlotRows returns each table row of the document with its spacing and
// code spans removed, so a slot row must match a whole row and not part of a
// longer one.
func documentedSlotRows(doc string) map[string]bool {
	rows := make(map[string]bool)
	normalize := strings.NewReplacer(" ", "", "\t", "", "\r", "", "`", "")
	for _, line := range strings.Split(doc, "\n") {
		if row := normalize.Replace(line); strings.HasPrefix(row, "|") {
			rows[row] = true
		}
	}
	return rows
}

func TestFrameworkAllowlistRunsBeforeAuthorTEAL(t *testing.T) {
	for _, test := range authorAllowlistCases {
		t.Run(test.name, func(t *testing.T) {
			provider := authorAllowlistProvider(t, authorAllowlistYAML(test))
			if got := provider.Layer3PolicyName(); got != test.stored {
				t.Fatalf("Layer3PolicyName() = %q, want %q", got, test.stored)
			}
			teal, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), authorAllowlistParams(nil))
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			done := "__aplane_bounded1_layer3_done:"
			if test.policy == composeddsa.Layer3PolicyMerkleAllowlist {
				done = "__aplane_bounded1_merkle_done:"
			}
			author := fmt.Sprintf("arg %d\nsha256", test.preimageAt)
			accept := "__aplane_bounded1_accept:"
			doneAt, authorAt, acceptAt := strings.Index(teal, done), strings.Index(teal, author), strings.LastIndex(teal, accept)
			if doneAt < 0 || authorAt < doneAt || acceptAt < authorAt {
				t.Fatalf("order done=%d author=%d accept=%d, want list before author TEAL before accept:\n%s",
					doneAt, authorAt, acceptAt, teal)
			}
			if strings.Contains(teal[doneAt:authorAt], "bnz") || strings.Contains(teal[doneAt:authorAt], "\nb ") {
				t.Fatalf("code between the list and author TEAL can branch away:\n%s", teal[doneAt:authorAt])
			}
			// The spending-key rekey accepts before the spend path, so neither the
			// list nor the author TEAL sees it.
			rekeyAt, spendAt := strings.Index(teal, "__aplane_bounded1_rekey:"), strings.Index(teal, "__aplane_bounded1_spend:")
			if rekeyAt < 0 || spendAt < rekeyAt || !strings.HasSuffix(teal[rekeyAt:spendAt], "b __aplane_bounded1_accept\n\n") ||
				strings.Index(teal, "// === framework-owned") < spendAt || authorAt < spendAt {
				t.Fatalf("spending-key rekey does not accept before the list and author TEAL:\n%s", teal)
			}
		})
	}
}

// The allowlist's parameters and arguments are unchanged by this feature, so a
// template with no author TEAL must keep its plain policy and reject what only
// author TEAL could use.
func TestFrameworkPolicyCombinationRejections(t *testing.T) {
	fixed, merkle := authorAllowlistCases[0], authorAllowlistCases[1]
	withoutAuthorTEAL := func(yaml string) string {
		return yaml[:strings.Index(yaml, "template_variables:")]
	}
	withoutRuntimeArgs := func(yaml string) string {
		return yaml[:strings.Index(yaml, "  runtime_args:")] + yaml[strings.Index(yaml, "\nparameters:"):]
	}
	withoutHash := func(yaml string) string {
		return strings.Replace(yaml, "  - name: hash\n    type: bytes\n    required: true\n    max_length: 64\n", "", 1)
	}
	for _, test := range []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "stored fixed value cannot be declared",
			yaml: strings.Replace(authorAllowlistYAML(fixed), "policy: fixed_allowlist", "policy: fixed_allowlist_custom", 1),
			want: "unsupported policy",
		},
		{
			name: "stored merkle value cannot be declared",
			yaml: strings.Replace(authorAllowlistYAML(merkle), "policy: merkle_allowlist", "policy: merkle_allowlist_custom", 1),
			want: "unsupported policy",
		},
		// The framework timelock is gone: its three policies cannot be declared.
		{
			name: "retired timelock cannot be declared",
			yaml: strings.Replace(authorAllowlistYAML(fixed), "policy: fixed_allowlist", "policy: timelock", 1),
			want: `unsupported policy "timelock"`,
		},
		{
			name: "retired fixed allowlist timelock cannot be declared",
			yaml: strings.Replace(authorAllowlistYAML(fixed), "policy: fixed_allowlist", "policy: fixed_allowlist_timelock", 1),
			want: `unsupported policy "fixed_allowlist_timelock"`,
		},
		{
			name: "retired merkle allowlist timelock cannot be declared",
			yaml: strings.Replace(authorAllowlistYAML(merkle), "policy: merkle_allowlist", "policy: merkle_allowlist_timelock", 1),
			want: `unsupported policy "merkle_allowlist_timelock"`,
		},
		{
			name: "extra parameter needs author TEAL",
			yaml: withoutRuntimeArgs(withoutAuthorTEAL(authorAllowlistYAML(fixed))),
			want: "is not used by framework policy",
		},
		{
			name: "runtime argument needs author TEAL",
			yaml: withoutHash(withoutAuthorTEAL(authorAllowlistYAML(fixed))),
			want: "has no author TEAL",
		},
		{
			name: "author TEAL cannot return",
			yaml: strings.Replace(authorAllowlistYAML(fixed), "  assert\n", "  assert\n  int 1\n  return\n", 1),
			want: "must not contain return",
		},
		{
			name: "author TEAL cannot jump to the accept block",
			yaml: strings.Replace(authorAllowlistYAML(fixed), "  assert\n", "  assert\n  b __aplane_bounded1_accept\n", 1),
			want: "reserved bounded label",
		},
		{
			name: "author TEAL cannot jump back into the list",
			yaml: strings.Replace(authorAllowlistYAML(merkle), "  assert\n", "  assert\n  b __aplane_bounded1_merkle_done\n", 1),
			want: "reserved bounded label",
		},
		{
			name: "fixed allowlist still takes no derived argument",
			yaml: strings.Replace(authorAllowlistYAML(fixed), "  runtime_args:\n", strings.TrimPrefix(merkle.derived, "\n")+"\n  runtime_args:\n", 1),
			want: "does not accept derived arguments",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			falcon1024.RegisterClient()
			err := authorAllowlistError([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func authorAllowlistError(yaml []byte) error {
	spec, err := composeddsa.ParseTemplateSpec(yaml)
	if err != nil {
		return err
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		return err
	}
	_, err = provider.GenerateTEAL(bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), authorAllowlistParams(nil))
	return err
}

// A framework policy's encoding is hashed into its compatibility fingerprint. A
// plain allowlist must encode exactly as it always has, or installed templates
// would report a conflict.
func TestLayer3PolicyFingerprintEncoding(t *testing.T) {
	encoded, err := json.Marshal(composeddsa.Layer3Policy{Policy: composeddsa.Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"policy":"fixed_allowlist","recipients_parameter":"recipients"}`; string(encoded) != want {
		t.Fatalf("encoded policy = %s, want %s", encoded, want)
	}
}
