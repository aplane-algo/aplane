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
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	timelockProfileHex       = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000008626f756e6465643200000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000077265667573656400000000000000000000000874696d656c6f636b000000010000058f0000000000000000000000010000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564"
	fixedTimelockProfileHex  = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000008626f756e6465643200000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000077265667573656400000000000000000000001866697865645f616c6c6f776c6973745f74696d656c6f636b000000010000058f0000000000000000000000010000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564"
	merkleTimelockProfileHex = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000008626f756e6465643200000003000000037061790000000561786665720000000c61737365745f6f70745f696e000000000000271000000007726566757365640000000000000000000000196d65726b6c655f616c6c6f776c6973745f74696d656c6f636b000000010000058f000000010000000c6d65726b6c655f70726f6f66000000166d65726b6c655f616c6c6f776c6973745f70726f6f660000000a726563697069656e74730000020000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e61747572650000058f000000087265717569726564000000087265717569726564000000087265717569726564000000010000000c6d65726b6c655f70726f6f66000000076465726976656400000200000000086f7074696f6e616c00000009666f7262696464656e00000009666f7262696464656e"

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
	timelockRefusedRekeyYAML     = "  rekey: refused\n"
	timelockSpendingKeyRekeyYAML = "  rekey: spending_key\n"
	testUnlockRound              = "50000000"
	timelockBlock                = "// === framework-owned timelock ===\ntxn FirstValid\npushint 50000000\n>=\nassert\n\n"
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
		length:     218,
		slots:      []string{"|0|base_signature_0|base_signature|1423|required|required|"},
	},
	{
		policy:     composeddsa.Layer3PolicyFixedAllowlistTimelock,
		plain:      composeddsa.Layer3PolicyFixedAllowlist,
		maxItems:   composeddsa.BoundedInlineListMax,
		profileHex: fixedTimelockProfileHex,
		length:     234,
		slots:      []string{"|0|base_signature_0|base_signature|1423|required|required|"},
	},
	{
		policy:     composeddsa.Layer3PolicyMerkleAllowlistTimelock,
		plain:      composeddsa.Layer3PolicyMerkleAllowlist,
		maxItems:   65536,
		derived:    timelockDerivedYAML,
		profileHex: merkleTimelockProfileHex,
		length:     368,
		slots: []string{
			"|0|base_signature_0|base_signature|1423|required|required|",
			"|1|merkle_proof|derived|512|optional|forbidden|",
		},
	},
}

func (test timelockCase) hasList() bool {
	return test.maxItems != 0
}

// yaml takes the rekey setting and an optional cosigner block.
func (test timelockCase) yaml(rekey, cosigner string) string {
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
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
%s%s  layer3:
    policy: %s
    unlock_round_parameter: unlock_round%s%s

parameters:
%s%s`, rekey, cosigner, test.policy, recipientsParameter, test.derived, timelockParameterYAML, recipients)
}

// defaultYAML refuses rekeys, the only setting a timelock policy accepts: no host
// rule gates a rekey, so a spending-key rekey would leave the lock early.
func (test timelockCase) defaultYAML() string {
	return test.yaml(timelockRefusedRekeyYAML, "")
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
	rows := documentedSlotRows(string(data))
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
				if !rows[row] {
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

// A timelock refuses rekeys, and with no rekey path every one of the seven spend
// subsets compiles. A spending-key rekey is refused for each of them: pay no
// longer makes it acceptable, because no host rule gates a rekey.
// A timelock refuses rekeys, and an account that refuses rekeys must keep a
// transfer for what it holds, so a timelock template is limited to the subsets
// with pay, and with axfer whenever it can opt in. The others would trap funds.
func TestTimelockPolicySpendSubsets(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	subsets := map[string]string{
		"pay": "", "pay, axfer": "", "pay, axfer, asset_opt_in": "",
		"axfer":               "needs pay in spend_effects",
		"asset_opt_in":        "needs pay in spend_effects",
		"axfer, asset_opt_in": "needs pay in spend_effects",
		"pay, asset_opt_in":   "needs axfer in spend_effects",
	}
	for _, test := range timelockCases {
		for subset, trapped := range subsets {
			t.Run(test.policy+"/"+subset, func(t *testing.T) {
				effects := "spend_effects: [" + subset + "]"
				refused := strings.Replace(test.yaml(timelockRefusedRekeyYAML, ""), "spend_effects: [pay, axfer, asset_opt_in]", effects, 1)
				if trapped != "" {
					if err := timelockGenerateError(refused, test.params(nil)); err == nil || !strings.Contains(err.Error(), trapped) {
						t.Fatalf("refused-rekey error = %v, want %q", err, trapped)
					}
					return
				}
				if _, err := authorAllowlistProvider(t, refused).GenerateTEAL(publicKey, test.params(nil)); err != nil {
					t.Fatalf("refused-rekey GenerateTEAL() error = %v", err)
				}
				spendingKey := strings.Replace(test.yaml(timelockSpendingKeyRekeyYAML, ""), "spend_effects: [pay, axfer, asset_opt_in]", effects, 1)
				if err := timelockGenerateError(spendingKey, test.params(nil)); err == nil || !strings.Contains(err.Error(), "can't take rekey: spending_key") {
					t.Fatalf("spending-key rekey error = %v, want the refused-rekey requirement", err)
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
		{name: "runtime argument has no reader", yaml: replace(bare, "\nparameters:\n", "  runtime_args:\n    - name: extra\n      type: bytes\n      max_size: 8\n      required_on: [spend]\n\nparameters:\n"), want: "has no author TEAL"},
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
		// An expert template is held to the same rule as the general type: no host
		// rule gates a rekey, so a spending-key rekey would leave the lock early.
		cases = append(cases, struct {
			name   string
			yaml   string
			params map[string]string
			want   string
		}{
			name:   test.policy + " refuses a spending-key rekey",
			yaml:   test.yaml(timelockSpendingKeyRekeyYAML, ""),
			params: test.params(nil),
			want:   fmt.Sprintf("policy %q can't take rekey: spending_key: a spending-key rekey would leave the lock before the unlock round; use rekey: only_these, or refused", test.policy),
		})
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
	cosignerKey := hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
	type budget struct {
		bytecode, spendArgs, spendGroup int
		spendFee                        uint64
	}
	// A timelock takes no spending-key rekey, so these are its two arrangements
	// that refuse rekeys. The general type's timelock takes a rekey-to list
	// instead, which this matrix does not measure. The cosigned rows grew by the
	// cosigner check's callsub and retsub, and their fee with the program size.
	refused, cosigned := "refused", "refused and cosigner"
	want := map[string]budget{
		composeddsa.Layer3PolicyTimelock + "/" + refused:                 {bytecode: 1889, spendArgs: 1423, spendGroup: 2, spendFee: 2000},
		composeddsa.Layer3PolicyTimelock + "/" + cosigned:                {bytecode: 3741, spendArgs: 2846, spendGroup: 3, spendFee: 3076},
		composeddsa.Layer3PolicyFixedAllowlistTimelock + "/" + refused:   {bytecode: 3110, spendArgs: 1423, spendGroup: 2, spendFee: 2112},
		composeddsa.Layer3PolicyFixedAllowlistTimelock + "/" + cosigned:  {bytecode: 4959, spendArgs: 2846, spendGroup: 3, spendFee: 3198},
		composeddsa.Layer3PolicyMerkleAllowlistTimelock + "/" + refused:  {bytecode: 2153, spendArgs: 1935, spendGroup: 2, spendFee: 2016},
		composeddsa.Layer3PolicyMerkleAllowlistTimelock + "/" + cosigned: {bytecode: 3999, spendArgs: 3358, spendGroup: 4, spendFee: 4002},
	}
	for _, test := range timelockCases {
		for _, arrangement := range []string{refused, cosigned} {
			name := test.policy + "/" + arrangement
			t.Run(name, func(t *testing.T) {
				params := map[string]string{"unlock_round": "18446744073709551615"}
				if test.maxItems == composeddsa.BoundedInlineListMax {
					params["recipients"] = strings.Join(recipients, ",")
				} else if test.hasList() {
					params["recipients"] = recipients[0]
				}
				cosigner := ""
				if arrangement == cosigned {
					cosigner = timelockCosignerYAML
					params[composeddsa.BoundedCosignerPublicKeyParameter] = cosignerKey
				}
				yaml := test.yaml(timelockRefusedRekeyYAML, cosigner)
				bytecode, metadata := compileTimelockProgram(t, client, authorAllowlistProvider(t, yaml), publicKey, params)
				got := budget{bytecode: len(bytecode), spendArgs: metadata.ArgumentBytesForPath(boundedmeta.PathSpend)}
				spendPlan := solveV42BundledPath(t, consensus, len(bytecode), got.spendArgs)
				got.spendGroup, got.spendFee = int(spendPlan.GroupSize), v42BundledPathFee(spendPlan)
				if got != want[name] {
					t.Errorf("budget = %#v", got)
				}
				if got.spendFee > *metadata.MaxFee {
					t.Fatalf("path fee exceeds bounded maximum %d: %#v", *metadata.MaxFee, got)
				}
			})
		}
	}
}
