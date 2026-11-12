// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

func registerTemplateTestBase(t testing.TB, keyType string) {
	t.Helper()
	familyName := strings.TrimSuffix(keyType, "-v1")
	if dot := strings.Index(familyName, "."); dot >= 0 {
		familyName = familyName[dot+1:]
	}
	familyName = strings.TrimSuffix(familyName, ".v1")
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       keyType,
		FamilyName:        familyName,
		Version:           1,
		Ops:               testOps{construction: catalogConstruction(keyType)},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
}

// catalogConstruction is the construction a catalog base name requires of its ops,
// or the zero value for a name outside the catalog.
func catalogConstruction(baseKeyType string) sigconstruction.Construction {
	construction, _ := sigconstruction.ForBaseKeyType(baseKeyType)
	return construction
}

func TestValidateTemplateSpecAcceptsComposedRegisteredBase(t *testing.T) {
	registerTemplateTestBase(t, "test.template-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-base.v1
template_mode: generated
publisher: test
family: template-base-allowlist
version: 1
display_name: "Template Base Allowlist"
valid_rekey_target: true
parameters:
  - name: recipient
    type: address
    required: true
teal: |
  txn Receiver
  addr @recipient
  ==
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("ValidateTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if provider.KeyType() != "test.template-base-allowlist.v1" {
		t.Fatalf("KeyType() = %q, want test.template-base-allowlist.v1", provider.KeyType())
	}
	if got := provider.LogicSigOpcodeProfile(); got != lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling) {
		t.Fatalf("LogicSigOpcodeProfile() = %#v, want one-member default", got)
	}
}

func TestNewProviderFromTemplateSpecUsesDerivationVersion(t *testing.T) {
	registerTemplateTestBase(t, "test.template-derivation-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: test.template-derivation-base.v1
template_mode: generated
publisher: test
family: template-derivation
version: 1
display_name: "Template Derivation"
valid_rekey_target: true
max_opcode_cost: 20000
teal: |
  int 1
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if got := provider.fingerprintSaltStyle(); got != string(lsigsalt.StyleAlgodAutoSalt) {
		t.Fatalf("fingerprintSaltStyle() = %q, want %q", got, lsigsalt.StyleAlgodAutoSalt)
	}
}

func TestNewProviderFromTemplateSpecOmittedDerivationUsesNoSalt(t *testing.T) {
	registerTemplateTestBase(t, "test.template-unsalted-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-unsalted-base.v1
template_mode: generated
publisher: test
family: template-unsalted
version: 1
display_name: "Template Unsalted"
valid_rekey_target: true
max_opcode_cost: 20000
teal: |
  int 1
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if got := provider.fingerprintSaltStyle(); got != string(lsigsalt.StyleNone) {
		t.Fatalf("fingerprintSaltStyle() = %q, want %q", got, lsigsalt.StyleNone)
	}
}

func TestValidateTemplateSpecRejectsInvalidBaseKeyType(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing base",
			yaml: `
schema_version: 1
template_type: composed
template_mode: generated
publisher: test
family: missing-base
version: 1
display_name: "Missing Base"
valid_rekey_target: true
teal: |
  int 1
`,
			want: "base_key_type is required for composed templates",
		},
		{
			name: "unknown base",
			yaml: `
schema_version: 1
template_type: composed
base_key_type: unknown-base-v1
template_mode: generated
publisher: test
family: unknown-base
version: 1
display_name: "Unknown Base"
valid_rekey_target: true
teal: |
  int 1
`,
			want: `base_key_type "unknown-base-v1" is not registered as composable`,
		},
		{
			name: "generic template type",
			yaml: `
schema_version: 1
template_type: generic
base_key_type: template-base-v1
template_mode: generated
publisher: test
family: wrong-type
version: 1
display_name: "Wrong Type"
valid_rekey_target: true
teal: |
  int 1
`,
			want: `template_type must be "composed" for composed templates`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseTemplateSpec([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("ParseTemplateSpec() error = %v", err)
			}
			err = ValidateTemplateSpec(spec)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateTemplateSpec() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseTemplateSpecRejectsSaltStyle(t *testing.T) {
	_, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-base.v1
template_mode: generated
publisher: test
family: salt-style
version: 1
display_name: "Salt Style"
valid_rekey_target: true
salt_style: pushbytes
teal: |
  int 1
`))
	if err == nil {
		t.Fatal("ParseTemplateSpec() error = nil, want salt_style rejection")
	}
	if !strings.Contains(err.Error(), "salt_style is not supported") {
		t.Fatalf("ParseTemplateSpec() error = %v, want salt_style rejection", err)
	}
}

func TestComposedSchemaV2BuildsBoundedProvider(t *testing.T) {
	baseKeyType := "test.template-bounded-base.v1"
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       baseKeyType,
		FamilyName:        "template-bounded-base",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 2
template_type: composed
base_key_type: test.template-bounded-base.v1
template_mode: strict
publisher: test
family: template-bounded
version: 1
display_name: Template Bounded
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [axfer, pay]
  max_fee: 10000
  rekey: spending_key
  runtime_args:
    - name: preimage
      type: bytes
      max_size: 64
      required_on: [spend]
teal: |
  int 1
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	profile := provider.BoundedAuthorizationProfile()
	if profile == nil || profile.Contract != BoundedContract || profile.MaxFee == nil || *profile.MaxFee != 10_000 || profile.Rekey != boundedmeta.RekeySpendingKey {
		t.Fatalf("BoundedAuthorizationProfile() = %#v", profile)
	}
	if got := provider.CreationParams(); len(got) != 0 {
		t.Fatalf("CreationParams() = %#v, want no injected parameters", got)
	}
	if got := provider.RuntimeArgs(); len(got) != 1 || got[0].Name != "preimage" || got[0].MaxSize != 64 || !got[0].Required {
		t.Fatalf("RuntimeArgs() = %#v, want bounded preimage", got)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || len(metadata.ArgumentLayout) != 2 || metadata.ArgumentLayout[1].Source != boundedmeta.ArgSourceRuntime {
		t.Fatalf("BoundedAuthorizationMetadata() = %#v, want base/runtime layout", metadata)
	}
}

// The bounded_ prefix stays reserved for the framework, so the retired admin
// parameter name cannot come back as an author parameter.
func TestComposedSchemaV2RejectsAuthorDeclaredReservedBoundedParameter(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       "aplane.falcon1024.v1",
		FamilyName:        "falcon1024",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	spec, err := ParseTemplateSpec([]byte(`
schema_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: author-reserved
version: 1
display_name: Author Reserved
valid_rekey_target: true
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: spending_key
parameters:
  - name: bounded_example_key
    type: bytes
    required: true
    max_length: 3586
teal: |
  int 1
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	// Admission refuses it, so it can't be installed.
	if err := ValidateTemplateAdmission(spec); err == nil ||
		!strings.Contains(err.Error(), "invalid bounded template contract: ") || !strings.Contains(err.Error(), "reserved bounded_ prefix") {
		t.Fatalf("ValidateTemplateAdmission() error = %v, want reserved-prefix rejection", err)
	}
	// One already in a store still loads, and the mistake is refused when a key
	// is generated.
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	_, err = provider.GenerateTEAL([]byte{1}, map[string]string{"bounded_example_key": strings.Repeat("22", 1793)})
	if err == nil || !strings.Contains(err.Error(), "reserved bounded_ prefix") {
		t.Fatalf("GenerateTEAL() error = %v, want reserved-prefix rejection", err)
	}
}

func TestTemplateSchemaSelectionAndStrictDecoding(t *testing.T) {
	registerTemplateTestBase(t, "test.template-schema-selection-base.v1")
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "v1 bounded rejected",
			yaml: "schema_version: 1\nbounded: {}\n",
			want: "field bounded not found",
		},
		{
			name: "v2 bounded required",
			yaml: `schema_version: 2
template_type: composed
base_key_type: test.template-schema-selection-base.v1
publisher: test
family: missing-bounded
version: 1
display_name: Missing Bounded
valid_rekey_target: true
teal: int 1
`,
			want: "requires bounded",
		},
		{
			name: "unknown nested bounded field",
			yaml: "schema_version: 2\nbounded:\n  contract: bounded2\n  mystery: true\n",
			want: "field mystery not found",
		},
		{
			name: "administrative operations rejected",
			yaml: "schema_version: 2\nbounded:\n  admin_operations:\n    - kind: rekey\n",
			want: "field admin_operations not found",
		},
		{
			name: "unknown nested cosigner field",
			yaml: "schema_version: 2\nbounded:\n  cosigner:\n    contract: cosigner1\n    mystery: true\n",
			want: "field mystery not found",
		},
		{
			name: "duplicate nested field",
			yaml: "schema_version: 2\nbounded:\n  contract: bounded2\n  contract: bounded2\n",
			want: "duplicate field",
		},
		{
			name: "duplicate schema selector",
			yaml: "schema_version: 1\nschema_version: 2\n",
			want: "duplicate field",
		},
		{
			name: "non integer schema selector",
			yaml: "schema_version: two\n",
			want: "integer scalar",
		},
		{
			name: "merge key rejected",
			yaml: "schema_version: 2\nbounded:\n  <<: {contract: bounded2}\n",
			want: "merge keys are not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseTemplateSpec([]byte(tt.yaml))
			if err == nil && tt.name == "v2 bounded required" {
				err = ValidateTemplateSpec(spec)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestComposedSchemaV2BuildsBoundedCosignerProfile(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       "aplane.falcon1024.v1",
		FamilyName:        "falcon1024",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	spec, err := ParseTemplateSpec([]byte(`
schema_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: aplane
family: bounded-cosigner-test
version: 1
display_name: Bounded Cosigner Test
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
  cosigner:
    contract: cosigner1
    required_on: [spend]
teal: |
  int 1
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	params := provider.CreationParams()
	if len(params) != 1 || params[0].Name != BoundedCosignerPublicKeyParameter || params[0].MaxLength != boundedmeta.CosignerPublicKeySizeV1*2 {
		t.Fatalf("CreationParams() = %#v, want injected cosigner public key", params)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Cosigner == nil || metadata.Cosigner.Contract != boundedmeta.CosignerContractV1 || metadata.Rekey != boundedmeta.RekeyRefused {
		t.Fatalf("BoundedAuthorizationMetadata() = %#v", metadata)
	}
	if got := metadata.ArgumentLayout; len(got) != 2 || got[1].Source != boundedmeta.ArgSourceCosigner || got[1].Paths.Spend != boundedmeta.ArgRequired {
		t.Fatalf("ArgumentLayout = %#v, want base/cosigner layout", got)
	}
}

func TestComposedSchemaV2RejectsInvalidBoundedCosigner(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       "aplane.falcon1024.v1",
		FamilyName:        "falcon1024",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	registerTemplateTestBase(t, "test.non-falcon-bounded-cosigner.v1")
	base := `
schema_version: 2
template_type: composed
base_key_type: %s
template_mode: strict
publisher: test
family: invalid-bounded-cosigner
version: 1
display_name: Invalid Bounded Cosigner
valid_rekey_target: true
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
  cosigner:
    contract: %s
    required_on: [%s]
teal: |
  int 1
  assert
`
	tests := []struct {
		name, baseKeyType, contract, requiredOn, want string
	}{
		{name: "contract", baseKeyType: "aplane.falcon1024.v1", contract: "cosigner2", requiredOn: "spend", want: "unsupported bounded cosigner contract"},
		{name: "path", baseKeyType: "aplane.falcon1024.v1", contract: "cosigner1", requiredOn: "spending_rekey", want: "exactly [spend]"},
		{name: "base", baseKeyType: "test.non-falcon-bounded-cosigner.v1", contract: "cosigner1", requiredOn: "spend", want: "is not reviewed for base_key_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseTemplateSpec([]byte(fmt.Sprintf(base, tt.baseKeyType, tt.contract, tt.requiredOn)))
			if err == nil {
				err = ValidateTemplateSpec(spec)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestComposedSchemaV2RejectsInvalidBoundedArgumentContracts(t *testing.T) {
	baseKeyType := "test.template-bounded-args-base.v1"
	registerTemplateTestBase(t, baseKeyType)
	tests := []struct {
		name       string
		rekey      string
		bounded    string
		topLevel   string
		parameters string
		want       string
	}{
		{
			name:     "top-level runtime args",
			bounded:  "  runtime_args: []\n",
			topLevel: "runtime_args:\n  - name: preimage\n    type: bytes\n    required: true\n",
			want:     "must be declared inside bounded",
		},
		// A rekey never reaches Layer 3, so no runtime argument can be required on
		// it, even when the spending key may rekey.
		{
			name:    "runtime argument required on rekey",
			rekey:   "spending_key",
			bounded: "  runtime_args:\n    - name: preimage\n      type: bytes\n      max_size: 64\n      required_on: [spend, rekey]\n",
			want:    "must have required_on [spend]: a rekey never reaches Layer 3",
		},
		{
			name:    "runtime argument required only on rekey",
			rekey:   "spending_key",
			bounded: "  runtime_args:\n    - name: preimage\n      type: bytes\n      max_size: 64\n      required_on: [rekey]\n",
			want:    "must have required_on [spend]",
		},
		{
			name:    "runtime argument required on no path",
			bounded: "  runtime_args:\n    - name: preimage\n      type: bytes\n      max_size: 64\n      required_on: []\n",
			want:    "must have required_on [spend]",
		},
		{
			name:    "runtime argument required on spend twice",
			bounded: "  runtime_args:\n    - name: preimage\n      type: bytes\n      max_size: 64\n      required_on: [spend, spend]\n",
			want:    "must have required_on [spend]",
		},
		{
			name:       "derived source type",
			bounded:    "  derived_args:\n    - name: proof\n      kind: merkle_allowlist_proof\n      parameter: recipients\n      max_size: 512\n",
			parameters: "parameters:\n  - name: recipients\n    type: bytes\n    required: true\n",
			want:       "requires address[] parameter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rekey := tt.rekey
			if rekey == "" {
				rekey = "refused"
			}
			spec, err := ParseTemplateSpec([]byte(fmt.Sprintf(`schema_version: 2
template_type: composed
base_key_type: %s
template_mode: strict
publisher: test
family: bounded-args
version: 1
display_name: Bounded Args
valid_rekey_target: true
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: %s
%s%s%s
teal: |
  int 1
  assert
`, baseKeyType, rekey, tt.bounded, tt.parameters, tt.topLevel)))
			if err == nil {
				err = ValidateTemplateSpec(spec)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestComposedSchemaV2RequiresExplicitMaxFee(t *testing.T) {
	baseKeyType := "test.template-missing-max-fee-base.v1"
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       baseKeyType,
		FamilyName:        "template-missing-max-fee-base",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	spec, err := ParseTemplateSpec([]byte(`
schema_version: 2
template_type: composed
base_key_type: test.template-missing-max-fee-base.v1
template_mode: strict
publisher: test
family: missing-max-fee
version: 1
display_name: Missing Max Fee
valid_rekey_target: true
bounded:
  contract: bounded2
  spend_effects: [pay]
  rekey: refused
teal: int 1
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := ValidateTemplateSpec(spec); err == nil || !strings.Contains(err.Error(), "bounded.max_fee is required") {
		t.Fatalf("ValidateTemplateSpec() error = %v, want explicit max_fee rejection", err)
	}
}

// A bounded template states its rekey setting. The administrative operations
// that bounded1 had in its place are not read as either setting.
func TestComposedSchemaV2RequiresRekeySetting(t *testing.T) {
	baseKeyType := "test.template-rekey-setting-base.v1"
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       baseKeyType,
		FamilyName:        "template-rekey-setting-base",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	template := func(block string) string {
		return fmt.Sprintf(`
schema_version: 2
template_type: composed
base_key_type: %s
template_mode: strict
publisher: test
family: rekey-setting
version: 1
display_name: Rekey Setting
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
%steal: |
  int 1
  assert
`, baseKeyType, block)
	}
	for _, rekey := range []boundedmeta.RekeySetting{boundedmeta.RekeyRefused, boundedmeta.RekeySpendingKey} {
		spec, err := ParseTemplateSpec([]byte(template("  rekey: " + string(rekey) + "\n")))
		if err != nil {
			t.Fatalf("ParseTemplateSpec(%s) error = %v", rekey, err)
		}
		provider, err := NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatalf("NewProviderFromTemplateSpec(%s) error = %v", rekey, err)
		}
		if got := provider.BoundedAuthorizationProfile().Rekey; got != rekey {
			t.Fatalf("profile rekey = %q, want %q", got, rekey)
		}
		if got := provider.BoundedAuthorizationMetadata().Rekey; got != rekey {
			t.Fatalf("metadata rekey = %q, want %q", got, rekey)
		}
	}
	for _, tt := range []struct {
		name, spend, block, want string
	}{
		{name: "no rekey", block: "", want: "bounded.rekey is required: refused, spending_key, only_these or plus_cosigned"},
		{name: "empty rekey", block: "  rekey: \"\"\n", want: "bounded.rekey is required"},
		{name: "unknown rekey", block: "  rekey: admin_key\n", want: `unsupported rekey setting "admin_key"`},
		{name: "old gate value", block: "  rekey: layer3\n", want: `unsupported rekey setting "layer3"`},
		{
			name:  "administrative operations instead of rekey",
			block: "  admin_operations:\n    - kind: rekey\n      authorization: spending_key\n      policy_gate: layer3\n",
			want:  "field admin_operations not found",
		},
		{
			name:  "administrative operations beside rekey",
			block: "  rekey: spending_key\n  admin_operations:\n    - kind: rekey\n      authorization: spending_key\n      policy_gate: none\n",
			want:  "field admin_operations not found",
		},
		{name: "empty administrative operations", block: "  rekey: refused\n  admin_operations: []\n", want: "field admin_operations not found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			yaml := template(tt.block)
			if tt.spend != "" {
				yaml = strings.Replace(yaml, "spend_effects: [pay]", "spend_effects: "+tt.spend, 1)
			}
			spec, err := ParseTemplateSpec([]byte(yaml))
			if err == nil {
				err = ValidateTemplateSpec(spec)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateTemplateSpecRejectsNonRelocatableTEAL(t *testing.T) {
	registerTemplateTestBase(t, "test.relocatable-base.v1")

	tests := []struct {
		name string
		teal string
		want string
	}{
		{
			name: "bytecblock",
			teal: "bytecblock 0xabcd\nint 1",
			want: `composed template suffix: template TEAL must be relocatable: raw constant opcode "bytecblock" on line 1 is not allowed`,
		},
		{
			name: "intcblock",
			teal: "intcblock 1 2\nint 1",
			want: `composed template suffix: template TEAL must be relocatable: raw constant opcode "intcblock" on line 1 is not allowed`,
		},
		{
			name: "bytec short form",
			teal: "bytec_0\nint 1",
			want: `composed template suffix: template TEAL must be relocatable: raw constant opcode "bytec_0" on line 1 is not allowed`,
		},
		{
			name: "intc short form",
			teal: "intc_0\nint 1",
			want: `composed template suffix: template TEAL must be relocatable: raw constant opcode "intc_0" on line 1 is not allowed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseTemplateSpec([]byte(fmt.Sprintf(`
schema_version: 1
template_type: composed
base_key_type: test.relocatable-base.v1
template_mode: generated
publisher: test
family: non-relocatable-%s
version: 1
display_name: "Non Relocatable"
valid_rekey_target: true
teal: |
%s
`, strings.ReplaceAll(tt.name, " ", "-"), indentTEALForTest(tt.teal))))
			if err != nil {
				t.Fatalf("ParseTemplateSpec() error = %v", err)
			}
			err = ValidateTemplateSpec(spec)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateTemplateSpec() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateTemplateSpecAcceptsTemplateVariableSuffix(t *testing.T) {
	registerTemplateTestBase(t, "test.relocatable-strict-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.relocatable-strict-base.v1
template_mode: strict
publisher: test
family: relocatable-strict
version: 1
display_name: "Relocatable Strict"
valid_rekey_target: true
max_opcode_cost: 20000
parameters:
  - name: hash
    type: bytes
    required: true
template_variables:
  - name: hash
    source: parameter
    parameter: hash
    type: bytes
    constant: byte
runtime_args:
  - name: preimage
    type: bytes
    required: true
teal: |
  arg 1
  sha256
  $hash
  ==
  assert
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("ValidateTemplateSpec() error = %v", err)
	}
}

func TestPrepareKeystoreTemplateRegistrationRegistersDeriverWhenProviderExists(t *testing.T) {
	baseKeyType := "test.template-existing-provider-base.v1"
	registerTemplateTestBase(t, baseKeyType)

	data := []byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-existing-provider-base.v1
template_mode: generated
publisher: test
family: existing-provider
version: 1
display_name: "Existing Provider"
valid_rekey_target: true
max_opcode_cost: 20000
teal: |
  int 1
  assert
`)
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if !logicsigdsa.RegisterIfAbsent(provider) {
		t.Fatal("test provider was already registered")
	}

	prepared, err := PrepareKeystoreTemplateRegistration(provider.KeyType(), data)
	if err != nil {
		t.Fatalf("PrepareKeystoreTemplateRegistration() error = %v", err)
	}
	if added := prepared.Register(); added {
		t.Fatal("Register() = true, want false for existing provider")
	}
	if _, err := addressderive.Get(provider.KeyType()); err != nil {
		t.Fatalf("address deriver was not registered for existing provider: %v", err)
	}
}

func TestSemanticFingerprintIncludesBaseKeyType(t *testing.T) {
	for _, keyType := range []string{"fingerprint-a-v1", "fingerprint-b-v1"} {
		registerBaseForTest(t, BaseRegistration{
			BaseKeyType:       keyType,
			FamilyName:        "fingerprint-base",
			Version:           1,
			Ops:               testOps{},
			NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
		})
	}

	template := `
schema_version: 1
template_type: composed
base_key_type: %s
template_mode: generated
publisher: test
family: fingerprint-template
version: 1
display_name: "Fingerprint Template"
valid_rekey_target: true
max_opcode_cost: 20000
teal: |
  int 1
`
	a, err := SemanticFingerprint([]byte(fmt.Sprintf(template, "fingerprint-a-v1")))
	if err != nil {
		t.Fatalf("SemanticFingerprint(a) error = %v", err)
	}
	b, err := SemanticFingerprint([]byte(fmt.Sprintf(template, "fingerprint-b-v1")))
	if err != nil {
		t.Fatalf("SemanticFingerprint(b) error = %v", err)
	}
	if a == b {
		t.Fatal("SemanticFingerprint() did not include base_key_type")
	}
}

// A comment is not part of a template's definition, so one above schema_version
// moves neither the fingerprint nor the program.
func TestTemplateCommentDoesNotMoveTheFingerprint(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType: "aplane.falcon1024.v1", FamilyName: "falcon1024", Version: 1,
		Ops: falconBoundaryTestOps{}, NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	plain := []byte(FixedAllowlistFixtureYAML)
	commented := []byte("# DEPRECATED: a note for operators.\n# It is not part of the definition.\n" + FixedAllowlistFixtureYAML)
	want, err := SemanticFingerprint(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SemanticFingerprint(commented); err != nil || got != want {
		t.Fatalf("SemanticFingerprint(commented) = %q, %v, want %q", got, err, want)
	}
	programs := make([]string, 0, 2)
	for _, data := range [][]byte{plain, commented} {
		spec, err := ParseTemplateSpec(data)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		teal, err := provider.GenerateTEAL(make([]byte, provider.ops.PublicKeySize()), map[string]string{
			"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		})
		if err != nil {
			t.Fatal(err)
		}
		programs = append(programs, teal)
	}
	if programs[0] != programs[1] {
		t.Fatal("a comment changed the program")
	}
}

func indentTEALForTest(teal string) string {
	var lines []string
	for _, line := range strings.Split(teal, "\n") {
		lines = append(lines, "  "+line)
	}
	return strings.Join(lines, "\n")
}

// argLimitTestOps is a bounded-capable stub whose signature argument layout the
// test chooses.
type argLimitTestOps struct {
	boundedTestOps
	layout SignatureArgLayout
}

func (o argLimitTestOps) SignatureArgLayout() SignatureArgLayout { return o.layout }

func runtimeArgsYAMLForTest(indent string, count, maxSize int, requiredOn bool) string {
	var b strings.Builder
	for i := range count {
		fmt.Fprintf(&b, "%s- name: arg%d\n%s  type: bytes\n%s  max_size: %d\n", indent, i, indent, indent, maxSize)
		if requiredOn {
			fmt.Fprintf(&b, "%s  required_on: [spend]\n", indent)
		}
	}
	return b.String()
}

// requireRefusedAtAdmissionOnly pins where a refusal lives. Whatever want is, the
// load path (spec validation, the provider build, and the registration a store
// reload prepares) accepts the template, so one installed before a check existed
// keeps loading. Admission refuses it with want, or accepts it when want is
// empty. It returns the provider the load path built.
func requireRefusedAtAdmissionOnly(t *testing.T, data []byte, want string) *ComposedDSA {
	t.Helper()
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("ValidateTemplateSpec() error = %v, want none: the load path applies no limit", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v, want none: the load path applies no limit", err)
	}
	if _, err := PrepareKeystoreTemplateRegistration(spec.KeyType(), data); err != nil {
		t.Fatalf("PrepareKeystoreTemplateRegistration() error = %v, want none: a stored template still loads", err)
	}
	err = ValidateTemplateAdmission(spec)
	if want == "" {
		if err != nil {
			t.Fatalf("ValidateTemplateAdmission() error = %v", err)
		}
		return provider
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateTemplateAdmission() error = %v, want %q", err, want)
	}
	return provider
}

// The network refuses a LogicSig with more than 255 arguments or one argument
// over 4,096 bytes. A composed program carries the base's signature arguments
// ahead of the template's, so the count is of both. The refusal is an admission
// check: the same template still builds on the load path.
func TestComposedTemplateAdmissionRefusesArgumentsTheNetworkRefuses(t *testing.T) {
	oneSlot := SignatureArgLayout{Count: 1, MaxSizes: []int{4}}
	threeSlots := SignatureArgLayout{Count: 3, MaxSizes: []int{4, 4, 4}}
	tests := []struct {
		name        string
		layout      SignatureArgLayout
		runtimeArgs int
		maxSize     int
		want        string
	}{
		{name: "255 in total", layout: oneSlot, runtimeArgs: 254, maxSize: 8},
		{name: "256 in total", layout: oneSlot, runtimeArgs: 255, maxSize: 8, want: "256 arguments (1 signature, 255 runtime): a LogicSig carries at most 255"},
		{name: "255 in total with a three-argument signature", layout: threeSlots, runtimeArgs: 252, maxSize: 8},
		{name: "256 in total with a three-argument signature", layout: threeSlots, runtimeArgs: 253, maxSize: 8, want: "256 arguments (3 signature, 253 runtime): a LogicSig carries at most 255"},
		{name: "runtime argument at the size limit", layout: oneSlot, runtimeArgs: 1, maxSize: 4096},
		{name: "runtime argument over the size limit", layout: oneSlot, runtimeArgs: 1, maxSize: 4097, want: "runtime_arg arg0 is 4097 bytes: a LogicSig argument is at most 4096"},
		{name: "base signature argument at the size limit", layout: SignatureArgLayout{Count: 1, MaxSizes: []int{4096}}, runtimeArgs: 1, maxSize: 8},
		{name: "base signature argument over the size limit", layout: SignatureArgLayout{Count: 1, MaxSizes: []int{4097}}, runtimeArgs: 1, maxSize: 8, want: "base signature argument 0 is 4097 bytes: a LogicSig argument is at most 4096"},
		// A layout whose count and sizes disagree could hide an argument from
		// either check, so it is refused as it is for a bounded program.
		{name: "more sizes than the count", layout: SignatureArgLayout{Count: 1, MaxSizes: []int{2000, 5000}}, runtimeArgs: 1, maxSize: 8, want: "signature"},
		{name: "a count without sizes", layout: SignatureArgLayout{Count: 3}, runtimeArgs: 1, maxSize: 8, want: "signature"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseKeyType := fmt.Sprintf("test.template-arg-limit-base%d.v1", i)
			registerBaseForTest(t, BaseRegistration{
				BaseKeyType:       baseKeyType,
				FamilyName:        fmt.Sprintf("template-arg-limit-base%d", i),
				Version:           1,
				Ops:               argLimitTestOps{layout: tt.layout},
				NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
			})
			requireRefusedAtAdmissionOnly(t, []byte(fmt.Sprintf(`schema_version: 1
template_type: composed
base_key_type: %s
template_mode: generated
publisher: test
family: template-arg-limit
version: 1
display_name: "Template Arg Limit"
valid_rekey_target: true
max_opcode_cost: 20000
runtime_args:
%steal: |
  int 1
  assert
`, baseKeyType, runtimeArgsYAMLForTest("  ", tt.runtimeArgs, tt.maxSize, false))), tt.want)
		})
	}
}

// A base that doesn't describe its signature arguments still carries at least
// one, so the count allows for it.
func TestComposedTemplateCountsASignatureForAnUndescribedBase(t *testing.T) {
	for i, tt := range []struct {
		runtimeArgs int
		want        string
	}{
		{runtimeArgs: 254},
		{runtimeArgs: 255, want: "256 arguments (1 signature, 255 runtime): a LogicSig carries at most 255"},
	} {
		baseKeyType := fmt.Sprintf("test.template-arg-limit-plain-base%d.v1", i)
		registerBaseForTest(t, BaseRegistration{
			BaseKeyType:       baseKeyType,
			FamilyName:        fmt.Sprintf("template-arg-limit-plain-base%d", i),
			Version:           1,
			Ops:               testOps{construction: sigconstruction.Falcon1024()},
			NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
		})
		requireRefusedAtAdmissionOnly(t, []byte(fmt.Sprintf(`schema_version: 1
template_type: composed
base_key_type: %s
template_mode: generated
publisher: test
family: template-arg-limit-plain
version: 1
display_name: "Template Arg Limit"
valid_rekey_target: true
max_opcode_cost: 20000
runtime_args:
%steal: |
  int 1
  assert
`, baseKeyType, runtimeArgsYAMLForTest("  ", tt.runtimeArgs, 8, false))), tt.want)
	}
}

// A bounded template's signature and runtime arguments are counted when the
// template is installed, and again when a key is generated. A template already
// in a store still builds.
func TestComposedSchemaV2AdmissionRefusesTooManyArguments(t *testing.T) {
	baseKeyType := "test.template-bounded-arg-count-base.v1"
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       baseKeyType,
		FamilyName:        "template-bounded-arg-count-base",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	for _, tt := range []struct {
		name        string
		runtimeArgs int
		want        string
	}{
		{name: "255 in total", runtimeArgs: 254},
		{name: "256 in total", runtimeArgs: 255, want: "bounded argument_layout has 256 arguments: a LogicSig carries at most 255"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider := requireRefusedAtAdmissionOnly(t, []byte(fmt.Sprintf(`schema_version: 2
template_type: composed
base_key_type: %s
template_mode: strict
publisher: test
family: bounded-arg-count
version: 1
display_name: Bounded Arg Count
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
  runtime_args:
%steal: |
  int 1
  assert
`, baseKeyType, runtimeArgsYAMLForTest("    ", tt.runtimeArgs, 8, true))), tt.want)
			_, err := provider.BuildBoundedAuthorizationMetadata([]byte{1}, nil, []byte{1, 2, 3})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
				}
				return
			}
			// The stored template loads, but no key can be generated from it.
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v, want %q", err, tt.want)
			}
		})
	}
}

// A bounded template whose LogicSig the network would refuse can't be installed,
// and no key can be generated from one already in a store, which still loads.
// That covers an oversized runtime argument and a count that only the cosigner
// slot takes past 255.
func TestComposedSchemaV2NeverYieldsArgumentsTheNetworkRefuses(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       "aplane.falcon1024.v1",
		FamilyName:        "falcon1024",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	const cosigner = "  cosigner:\n    contract: cosigner1\n    required_on: [spend]\n"
	for _, tt := range []struct {
		name        string
		cosigner    string
		runtimeArgs int
		maxSize     int
		want        string // at admission
		wantKeygen  string // at key generation, from a template already stored
	}{
		{name: "runtime argument at the size limit", runtimeArgs: 1, maxSize: 4096},
		{name: "runtime argument over the size limit", runtimeArgs: 1, maxSize: 4097,
			want:       "runtime_arg arg0 is 4097 bytes: a LogicSig argument is at most 4096",
			wantKeygen: "(arg0) is 4097 bytes: a LogicSig argument is at most 4096"},
		{name: "255 in total with the cosigner slot", cosigner: cosigner, runtimeArgs: 253, maxSize: 8},
		{name: "256 in total with the cosigner slot", cosigner: cosigner, runtimeArgs: 254, maxSize: 8,
			want:       "bounded argument_layout has 256 arguments: a LogicSig carries at most 255",
			wantKeygen: "bounded argument_layout has 256 arguments: a LogicSig carries at most 255"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider := requireRefusedAtAdmissionOnly(t, []byte(fmt.Sprintf(`schema_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: aplane
family: bounded-arg-limit
version: 1
display_name: Bounded Arg Limit
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
%s  runtime_args:
%steal: |
  int 1
  assert
`, tt.cosigner, runtimeArgsYAMLForTest("    ", tt.runtimeArgs, tt.maxSize, true))), tt.want)
			params := map[string]string{}
			if tt.cosigner != "" {
				params[BoundedCosignerPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x42}, boundedmeta.CosignerPublicKeySizeV1))
			}
			_, err := provider.BuildBoundedAuthorizationMetadata(bytes.Repeat([]byte{0x31}, boundedmeta.CosignerPublicKeySizeV1), params, []byte{1, 2, 3})
			if tt.wantKeygen == "" {
				if err != nil {
					t.Fatalf("key metadata: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantKeygen) {
				t.Fatalf("key metadata: error = %v, want %q", err, tt.wantKeygen)
			}
		})
	}
}

// A composed template declares valid_rekey_target too: install requires it,
// and the provider reads the declared value.
func TestComposedValidRekeyTargetIsRequiredAtAdmission(t *testing.T) {
	registerTemplateTestBase(t, "test.rekey-target-base.v1")
	const base = `schema_version: 1
template_type: composed
base_key_type: test.rekey-target-base.v1
template_mode: generated
publisher: test
family: falcon1024-rekey-target-declaration
version: 1
display_name: "Composed Rekey Target Declaration"
max_opcode_cost: 20000
%steal: |
  int 1
  assert
`
	for _, tc := range []struct {
		name, declaration string
		want, admitted    bool
	}{
		{"absent", "", false, false},
		{"false", "valid_rekey_target: false\n", false, true},
		{"true", "valid_rekey_target: true\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ParseTemplateSpec([]byte(fmt.Sprintf(base, tc.declaration)))
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateTemplateAdmission(spec)
			if !tc.admitted {
				if err == nil || !strings.Contains(err.Error(), "valid_rekey_target is required") {
					t.Fatalf("ValidateTemplateAdmission() error = %v, want valid_rekey_target required", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateTemplateAdmission() error = %v", err)
			}
			provider, err := NewProviderFromTemplateSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := provider.ValidRekeyTarget(); got != tc.want {
				t.Fatalf("ValidRekeyTarget() = %v, want %v", got, tc.want)
			}
		})
	}
}
