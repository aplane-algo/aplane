// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
	boundedprogram "github.com/aplane-algo/aplane/internal/boundedadmin/program"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	timelockProfileHex       = "0000001941504c414e455f424f554e4445445f50524f46494c455f563100000008626f756e6465643100000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000010000000572656b65790000000c7370656e64696e675f6b6579000000066c6179657233000000000000000874696d656c6f636b000000010000058f0000000000000000000000010000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564"
	fixedTimelockProfileHex  = "0000001941504c414e455f424f554e4445445f50524f46494c455f563100000008626f756e6465643100000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000010000000572656b65790000000c7370656e64696e675f6b6579000000066c6179657233000000000000001866697865645f616c6c6f776c6973745f74696d656c6f636b000000010000058f0000000000000000000000010000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564"
	merkleTimelockProfileHex = "0000001941504c414e455f424f554e4445445f50524f46494c455f563100000008626f756e6465643100000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000010000000572656b65790000000c7370656e64696e675f6b6579000000066c617965723300000000000000196d65726b6c655f616c6c6f776c6973745f74696d656c6f636b000000010000058f000000010000000c6d65726b6c655f70726f6f66000000166d65726b6c655f616c6c6f776c6973745f70726f6f660000000a726563697069656e74730000020000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564000000010000000c6d65726b6c655f70726f6f66000000076465726976656400000200000000086f7074696f6e616c00000009666f7262696464656e00000009666f7262696464656e"

	timelockParameterYAML = `  - name: unlock_round
    type: uint64
    required: true
    min: 1
`
	timelockDerivedYAML = `
  derived_args:
    - name: merkle_proof
      kind: merkle_allowlist_proof
      parameter: recipients
      max_size: 512`
	timelockCosignerYAML = `  cosigner:
    contract: cosigner1
    required_on: [spend]
`
	testUnlockRound = "50000000"
	timelockBlock   = "// === framework-owned timelock ===\ntxn FirstValid\npushint 50000000\n>=\nassert\n\n"
)

type timelockCase struct {
	policy     string
	plain      string
	maxItems   int
	derived    string
	profileHex string
	length     int
	slots      []string
}

var timelockCases = []timelockCase{
	{
		policy:     composeddsa.Layer3PolicyTimelock,
		profileHex: timelockProfileHex,
		length:     242,
		slots:      []string{"|0|base_signature_0|base_signature|1423|required|required|required|"},
	},
	{
		policy:     composeddsa.Layer3PolicyFixedAllowlistTimelock,
		plain:      composeddsa.Layer3PolicyFixedAllowlist,
		maxItems:   composeddsa.BoundedInlineListMax,
		profileHex: fixedTimelockProfileHex,
		length:     258,
		slots:      []string{"|0|base_signature_0|base_signature|1423|required|required|required|"},
	},
	{
		policy:     composeddsa.Layer3PolicyMerkleAllowlistTimelock,
		plain:      composeddsa.Layer3PolicyMerkleAllowlist,
		maxItems:   65536,
		derived:    timelockDerivedYAML,
		profileHex: merkleTimelockProfileHex,
		length:     392,
		slots: []string{
			"|0|base_signature_0|base_signature|1423|required|required|required|",
			"|1|merkle_proof|derived|512|optional|forbidden|forbidden|",
		},
	},
}

func (test timelockCase) hasList() bool {
	return test.maxItems != 0
}

// yaml uses a Layer-3-gated spending-key rekey unless told otherwise, so the
// default program covers every path the timelock applies to.
func (test timelockCase) yaml(authorization, gate, cosigner string) string {
	recipientsParameter, recipients := "", ""
	if test.hasList() {
		recipientsParameter = "\n    recipients_parameter: recipients"
		recipients = fmt.Sprintf(`  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: %d
`, test.maxItems)
	}
	return fmt.Sprintf(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: timelock-rules
version: 1
display_name: "Timelock Rules"
max_opcode_cost: 20000

bounded:
  contract: bounded1
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: %s
      policy_gate: %s
%s  layer3:
    policy: %s
    unlock_round_parameter: unlock_round%s%s

parameters:
%s%s`, authorization, gate, cosigner, test.policy, recipientsParameter, test.derived, timelockParameterYAML, recipients)
}

func (test timelockCase) defaultYAML() string {
	return test.yaml(boundedmeta.AdminAuthorizationSpend, boundedmeta.PolicyGateLayer3, "")
}

func (test timelockCase) params(extra map[string]string) map[string]string {
	params := map[string]string{"unlock_round": testUnlockRound}
	if test.hasList() {
		params["recipients"] = types.Address{1}.String()
	}
	for name, value := range extra {
		params[name] = value
	}
	return params
}

// These bytes were computed from the canonical encoding in ARCH_BOUNDED_DSA.md by
// a separate encoder, which first reproduced the author-TEAL vectors. They are not
// captured from this package's output.
func TestTimelockPolicyGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("../../docs/ARCH_BOUNDED_DSA.md")
	if err != nil {
		t.Fatalf("read ARCH_BOUNDED_DSA.md: %v", err)
	}
	doc := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "", "`", "").Replace(string(data))
	for _, test := range timelockCases {
		t.Run(test.policy, func(t *testing.T) {
			provider := authorAllowlistProvider(t, test.defaultYAML())
			metadata := provider.BoundedAuthorizationMetadata()
			if metadata == nil || metadata.Layer3Policy != test.policy {
				t.Fatalf("metadata = %#v, want layer3_policy %q", metadata, test.policy)
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
				test.policy + "_canonical_bounded_profile_length": fmt.Sprint(test.length),
				test.policy + "_canonical_bounded_profile_hex":    test.profileHex,
			} {
				if !strings.Contains(doc, label+":"+value) {
					t.Errorf("ARCH_BOUNDED_DSA.md does not document %s %q", label, value)
				}
			}
			for _, row := range test.slots {
				if !strings.Contains(doc, row) {
					t.Errorf("ARCH_BOUNDED_DSA.md does not document slot row %q", row)
				}
			}
		})
	}
}

// A combined policy must be the plain allowlist with only the timelock added, so
// the timelock cannot change what the list admits and the list cannot skip the
// timelock. This compares whole programs rather than looking for fragments.
func TestTimelockPolicyAddsOnlyTheTimelockToTheAllowlist(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	for _, test := range timelockCases {
		t.Run(test.policy, func(t *testing.T) {
			teal, err := authorAllowlistProvider(t, test.defaultYAML()).GenerateTEAL(publicKey, test.params(nil))
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			if got := strings.Count(teal, timelockBlock); got != 1 {
				t.Fatalf("timelock block appears %d times, want 1:\n%s", got, teal)
			}
			accept := strings.LastIndex(teal, "__aplane_bounded1_accept:")
			if lock := strings.Index(teal, timelockBlock); lock < 0 || accept < lock {
				t.Fatalf("timelock at %d, accept at %d", lock, accept)
			}
			if !test.hasList() {
				return
			}
			plainYAML := strings.Replace(test.defaultYAML(), "policy: "+test.policy, "policy: "+test.plain, 1)
			plainYAML = strings.Replace(plainYAML, "    unlock_round_parameter: unlock_round\n", "", 1)
			plainYAML = strings.Replace(plainYAML, timelockParameterYAML, "", 1)
			params := test.params(nil)
			delete(params, "unlock_round")
			plain, err := authorAllowlistProvider(t, plainYAML).GenerateTEAL(publicKey, params)
			if err != nil {
				t.Fatalf("plain GenerateTEAL() error = %v", err)
			}
			if got := strings.Replace(teal, timelockBlock, "", 1); got != plain {
				t.Fatalf("program without the timelock differs from the plain allowlist:\n%s\n---\n%s", got, plain)
			}
			if strings.Index(teal, timelockBlock) > strings.Index(teal, "// === framework-owned") {
				t.Fatalf("recipient check precedes the timelock:\n%s", teal)
			}
		})
	}
}

// A Layer-3-gated spending-key rekey reaches the recipient dispatch, which only
// has a branch for an effect the profile admits. Every subset containing pay
// therefore works on that route, and all seven work with an external admin key.
func TestTimelockPolicySpendSubsets(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	adminKey := hex.EncodeToString(bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize))
	subsets := []string{"pay", "axfer", "asset_opt_in", "pay, axfer", "pay, asset_opt_in", "axfer, asset_opt_in", "pay, axfer, asset_opt_in"}
	for _, test := range timelockCases {
		for _, subset := range subsets {
			t.Run(test.policy+"/"+subset, func(t *testing.T) {
				effects := "spend_effects: [" + subset + "]"
				admin := strings.Replace(test.yaml(boundedmeta.AdminAuthorizationAdmin, boundedmeta.PolicyGateNone, ""), "spend_effects: [pay, axfer, asset_opt_in]", effects, 1)
				params := test.params(map[string]string{composeddsa.BoundedAdminPublicKeyParameter: adminKey})
				if _, err := authorAllowlistProvider(t, admin).GenerateTEAL(publicKey, params); err != nil {
					t.Fatalf("admin-key GenerateTEAL() error = %v", err)
				}
				gated := strings.Replace(test.defaultYAML(), "spend_effects: [pay, axfer, asset_opt_in]", effects, 1)
				err := timelockGenerateError(gated, test.params(nil))
				if strings.Contains(subset, "pay") {
					if err != nil {
						t.Fatalf("gated rekey error = %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "requires pay in spend_effects") {
					t.Fatalf("gated rekey error = %v, want the pay requirement", err)
				}
			})
		}
	}
}

func timelockGenerateError(yaml string, params map[string]string) error {
	spec, err := composeddsa.ParseTemplateSpec([]byte(yaml))
	if err != nil {
		return err
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		return err
	}
	_, err = provider.GenerateTEAL(bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), params)
	return err
}

func TestTimelockPolicyRejections(t *testing.T) {
	bare, fixed, merkle := timelockCases[0], timelockCases[1], timelockCases[2]
	replace := func(test timelockCase, old, new string) string {
		yaml := test.defaultYAML()
		if !strings.Contains(yaml, old) {
			t.Fatalf("template does not contain %q", old)
		}
		return strings.Replace(yaml, old, new, 1)
	}
	authorTEAL := "\ntemplate_variables: []\n\nteal: |\n  txn Fee\n  pop\n"
	cases := []struct {
		name   string
		yaml   string
		params map[string]string
		want   string
	}{
		{name: "stored form cannot gain a custom suffix", yaml: replace(fixed, "policy: fixed_allowlist_timelock", "policy: fixed_allowlist_timelock_custom"), want: "unsupported policy"},
		{name: "unlock round parameter is required", yaml: replace(bare, "    unlock_round_parameter: unlock_round\n", ""), want: "unlock_round_parameter is required"},
		{name: "unlock round parameter must exist", yaml: replace(bare, "unlock_round_parameter: unlock_round", "unlock_round_parameter: missing"), want: "references unknown parameter"},
		{name: "unlock round must be uint64", yaml: replace(bare, "    type: uint64\n    required: true\n    min: 1\n", "    type: bytes\n    required: true\n    max_length: 8\n"), want: "must have type uint64"},
		{name: "unlock round must be required", yaml: replace(bare, "    required: true\n    min: 1\n", "    required: false\n    min: 1\n"), want: "must be required"},
		{name: "unlock round needs a minimum", yaml: replace(bare, "    min: 1\n", ""), want: "must set min >= 1"},
		{name: "unlock round minimum cannot be zero", yaml: replace(bare, "    min: 1\n", "    min: 0\n"), want: "must set min >= 1"},
		{name: "unlock round value cannot be zero", yaml: bare.defaultYAML(), params: bare.params(map[string]string{"unlock_round": "0"}), want: "invalid unlock_round"},
		{name: "bare timelock has no recipients", yaml: replace(bare, "    unlock_round_parameter: unlock_round\n", "    unlock_round_parameter: unlock_round\n    recipients_parameter: unlock_round\n"), want: "does not use recipients_parameter"},
		{name: "combined policy needs recipients", yaml: replace(fixed, "\n    recipients_parameter: recipients", ""), want: "recipients_parameter is required"},
		{name: "plain allowlist has no unlock round", yaml: replace(fixed, "policy: fixed_allowlist_timelock", "policy: fixed_allowlist"), want: "does not use unlock_round_parameter"},
		{name: "extra parameter is unused", yaml: fixed.defaultYAML() + "  - name: extra\n    type: uint64\n    required: true\n", want: "is not used by framework policy"},
		{name: "runtime argument has no reader", yaml: replace(bare, "\nparameters:\n", "  runtime_args:\n    - name: extra\n      type: bytes\n      max_size: 8\n      required_on: [spend, rekey]\n\nparameters:\n"), want: "has no author TEAL"},
		{name: "bare timelock takes no derived argument", yaml: replace(bare, "\n\nparameters:\n", timelockDerivedYAML+"\n\nparameters:\n"), want: "requires address[] parameter"},
		{name: "fixed timelock takes no derived argument", yaml: replace(fixed, "\n\nparameters:\n", timelockDerivedYAML+"\n\nparameters:\n"), want: "does not accept derived arguments"},
		{name: "merkle timelock needs its proof", yaml: replace(merkle, timelockDerivedYAML, ""), want: "requires exactly one derived Merkle proof argument"},
		{name: "fixed timelock keeps the inline limit", yaml: replace(fixed, "max_items: 30", "max_items: 31"), want: "max_items must be between 1 and 30"},
	}
	for _, test := range timelockCases {
		cases = append(cases, struct {
			name   string
			yaml   string
			params map[string]string
			want   string
		}{name: test.policy + " takes no author TEAL", yaml: test.defaultYAML() + authorTEAL, want: "does not accept author TEAL"})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			params := test.params
			if params == nil {
				params = fixed.params(nil)
			}
			err := timelockGenerateError(test.yaml, params)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTimelockPolicyAcceptsTheLargestRound(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	for _, test := range timelockCases {
		teal, err := authorAllowlistProvider(t, test.defaultYAML()).GenerateTEAL(publicKey, test.params(map[string]string{"unlock_round": "18446744073709551615"}))
		if err != nil {
			t.Fatalf("%s: GenerateTEAL() error = %v", test.policy, err)
		}
		if !strings.Contains(teal, "pushint 18446744073709551615\n") {
			t.Fatalf("%s: program does not compile the round:\n%s", test.policy, teal)
		}
	}
}

// The new field is hashed into every framework policy's compatibility
// fingerprint. A plain allowlist must encode exactly as it did before the field
// existed, or installed templates would report a conflict.
func TestLayer3PolicyFingerprintEncoding(t *testing.T) {
	encoded, err := json.Marshal(composeddsa.Layer3Policy{Policy: composeddsa.Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"policy":"fixed_allowlist","recipients_parameter":"recipients"}`; string(encoded) != want {
		t.Fatalf("encoded policy = %s, want %s", encoded, want)
	}
	fingerprint := func(yaml string) string {
		return authorAllowlistProvider(t, yaml).CompatibilityFingerprint()
	}
	test := timelockCases[1]
	renamed := strings.Replace(test.defaultYAML(), "unlock_round_parameter: unlock_round", "unlock_round_parameter: open_round", 1)
	renamed = strings.Replace(renamed, "- name: unlock_round", "- name: open_round", 1)
	if fingerprint(test.defaultYAML()) == fingerprint(renamed) {
		t.Fatal("fingerprint does not bind the unlock round parameter")
	}
	seen := make(map[string]string, len(timelockCases))
	for _, test := range timelockCases {
		value := fingerprint(strings.ReplaceAll(test.defaultYAML(), "max_items: 65536", "max_items: 30"))
		if other, ok := seen[value]; ok {
			t.Fatalf("%s and %s share a fingerprint", test.policy, other)
		}
		seen[value] = test.policy
	}
}

func TestExternalAdminValidatorAcceptsTimelockPolicies(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Fatal(err)
	}
	spendingKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	adminKey := bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)
	for _, test := range timelockCases {
		t.Run(test.policy, func(t *testing.T) {
			provider := authorAllowlistProvider(t, test.yaml(boundedmeta.AdminAuthorizationAdmin, boundedmeta.PolicyGateNone, ""))
			params := test.params(map[string]string{composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey)})
			bytecode, metadata := compileTimelockProgram(t, client, provider, spendingKey, params)
			binding, err := hex.DecodeString(metadata.ProgramBindingHex)
			if err != nil {
				t.Fatal(err)
			}
			if err := boundedprogram.Validate(bytecode, boundedprogram.Expected{
				SpendingPublicKey: spendingKey,
				AdminPublicKey:    adminKey,
				ProgramBinding:    binding,
				BaseArgCount:      1,
				AdminArgIndex:     len(test.slots),
				MaxFee:            10_000,
				SpendEffects:      []string{"pay", "axfer", "asset_opt_in"},
			}); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func compileTimelockProgram(t *testing.T, client *algod.Client, provider *composeddsa.ComposedDSA, publicKey []byte, params map[string]string) ([]byte, *boundedmeta.Metadata) {
	t.Helper()
	teal, err := provider.GenerateTEAL(publicKey, params)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	compiled, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(compiled.Result)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(publicKey, params, bytecode)
	if err != nil {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
	}
	return bytecode, metadata
}

// The inline lists are full and the unlock round is the longest value pushint can
// encode, which are the largest programs each policy can produce. Fees are
// microAlgos at a 1,000-microAlgo minimum with v42 program pricing.
func TestTimelockPolicyCompiledBudgetMatrix(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Fatal(err)
	}
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		t.Fatal(err)
	}
	recipients := make([]string, composeddsa.BoundedInlineListMax)
	for i := range recipients {
		address := types.Address{}
		address[0] = byte(i + 1)
		recipients[i] = address.String()
	}
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	adminKey := hex.EncodeToString(bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize))
	cosignerKey := hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
	type budget struct {
		bytecode, spendArgs, adminArgs, spendGroup, adminGroup int
		spendFee, adminFee                                     uint64
	}
	spending, admin, cosigned := "spending key", "admin key", "admin key and cosigner"
	want := map[string]budget{
		composeddsa.Layer3PolicyTimelock + "/" + spending:                {bytecode: 1932, spendArgs: 1423, spendGroup: 2, spendFee: 2000},
		composeddsa.Layer3PolicyTimelock + "/" + admin:                   {bytecode: 3837, spendArgs: 1423, adminArgs: 2846, spendGroup: 2, adminGroup: 3, spendFee: 2185, adminFee: 3085},
		composeddsa.Layer3PolicyTimelock + "/" + cosigned:                {bytecode: 5680, spendArgs: 2846, adminArgs: 2846, spendGroup: 3, adminGroup: 3, spendFee: 3270, adminFee: 3270},
		composeddsa.Layer3PolicyFixedAllowlistTimelock + "/" + spending:  {bytecode: 3153, spendArgs: 1423, spendGroup: 2, spendFee: 2116},
		composeddsa.Layer3PolicyFixedAllowlistTimelock + "/" + admin:     {bytecode: 5056, spendArgs: 1423, adminArgs: 2846, spendGroup: 2, adminGroup: 3, spendFee: 2307, adminFee: 3207},
		composeddsa.Layer3PolicyFixedAllowlistTimelock + "/" + cosigned:  {bytecode: 6898, spendArgs: 2846, adminArgs: 2846, spendGroup: 3, adminGroup: 3, spendFee: 3391, adminFee: 3391},
		composeddsa.Layer3PolicyMerkleAllowlistTimelock + "/" + spending: {bytecode: 2196, spendArgs: 1935, spendGroup: 2, spendFee: 2021},
		composeddsa.Layer3PolicyMerkleAllowlistTimelock + "/" + admin:    {bytecode: 4096, spendArgs: 1935, adminArgs: 2846, spendGroup: 2, adminGroup: 3, spendFee: 2211, adminFee: 3111},
		composeddsa.Layer3PolicyMerkleAllowlistTimelock + "/" + cosigned: {bytecode: 5938, spendArgs: 3358, adminArgs: 2846, spendGroup: 4, adminGroup: 3, spendFee: 4196, adminFee: 3295},
	}
	for _, test := range timelockCases {
		for _, arrangement := range []string{spending, admin, cosigned} {
			name := test.policy + "/" + arrangement
			t.Run(name, func(t *testing.T) {
				params := map[string]string{"unlock_round": "18446744073709551615"}
				if test.maxItems == composeddsa.BoundedInlineListMax {
					params["recipients"] = strings.Join(recipients, ",")
				} else if test.hasList() {
					params["recipients"] = recipients[0]
				}
				yaml := test.defaultYAML()
				if arrangement != spending {
					cosigner := ""
					params[composeddsa.BoundedAdminPublicKeyParameter] = adminKey
					if arrangement == cosigned {
						cosigner = timelockCosignerYAML
						params[composeddsa.BoundedCosignerPublicKeyParameter] = cosignerKey
					}
					yaml = test.yaml(boundedmeta.AdminAuthorizationAdmin, boundedmeta.PolicyGateNone, cosigner)
				}
				bytecode, metadata := compileTimelockProgram(t, client, authorAllowlistProvider(t, yaml), publicKey, params)
				got := budget{bytecode: len(bytecode), spendArgs: metadata.ArgumentBytesForPath(boundedmeta.PathSpend)}
				spendPlan := solveV42BundledPath(t, consensus, len(bytecode), got.spendArgs)
				got.spendGroup, got.spendFee = int(spendPlan.GroupSize), v42BundledPathFee(spendPlan)
				if metadata.RequiresAdminKey() {
					got.adminArgs = metadata.ArgumentBytesForPath(boundedmeta.PathAdminRekey)
					adminPlan := solveV42BundledPath(t, consensus, len(bytecode), got.adminArgs)
					got.adminGroup, got.adminFee = int(adminPlan.GroupSize), v42BundledPathFee(adminPlan)
				}
				if got != want[name] {
					t.Errorf("budget = %#v", got)
				}
				if got.spendFee > metadata.MaxFee || got.adminFee > metadata.MaxFee {
					t.Fatalf("path fee exceeds bounded maximum %d: %#v", metadata.MaxFee, got)
				}
			})
		}
	}
}
