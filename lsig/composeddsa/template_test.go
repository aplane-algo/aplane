// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

func registerTemplateTestBase(keyType string) {
	familyName := strings.TrimSuffix(keyType, "-v1")
	if dot := strings.Index(familyName, "."); dot >= 0 {
		familyName = familyName[dot+1:]
	}
	familyName = strings.TrimSuffix(familyName, ".v1")
	RegisterBase(BaseRegistration{
		BaseKeyType:       keyType,
		FamilyName:        familyName,
		Version:           1,
		Ops:               testOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
}

func TestValidateTemplateSpecAcceptsComposedRegisteredBase(t *testing.T) {
	registerTemplateTestBase("test.template-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-base.v1
template_mode: generated
publisher: test
family: template-base-allowlist
version: 1
display_name: "Template Base Allowlist"
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
}

func TestNewProviderFromTemplateSpecUsesDerivationVersion(t *testing.T) {
	registerTemplateTestBase("test.template-derivation-base.v1")

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
	registerTemplateTestBase("test.template-unsalted-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-unsalted-base.v1
template_mode: generated
publisher: test
family: template-unsalted
version: 1
display_name: "Template Unsalted"
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
	RegisterBase(BaseRegistration{
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
bounded:
  contract: bounded1
  spend_effects: [axfer, pay]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
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
	if profile == nil || profile.Contract != BoundedContractV1 || profile.MaxFee != 10_000 {
		t.Fatalf("BoundedAuthorizationProfile() = %#v", profile)
	}
	if got := provider.CreationParams(); len(got) != 1 || got[0].Name != BoundedAdminPublicKeyParameter {
		t.Fatalf("CreationParams() = %#v, want injected contract-admin public key", got)
	}
	if got := provider.RuntimeArgs(); len(got) != 1 || got[0].Name != "preimage" || got[0].MaxSize != 64 || !got[0].Required {
		t.Fatalf("RuntimeArgs() = %#v, want bounded preimage", got)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || len(metadata.ArgumentLayout) != 3 || metadata.ArgumentLayout[1].Source != boundedmeta.ArgSourceRuntime || metadata.ArgumentLayout[2].Source != boundedmeta.ArgSourceAdmin {
		t.Fatalf("BoundedAuthorizationMetadata() = %#v, want base/runtime/admin layout", metadata)
	}
}

func TestComposedSchemaV2RejectsAuthorDeclaredAdminPublicKey(t *testing.T) {
	baseKeyType := "test.template-author-admin-key-base.v1"
	registerTemplateTestBase(baseKeyType)
	spec, err := ParseTemplateSpec([]byte(`
schema_version: 2
template_type: composed
base_key_type: test.template-author-admin-key-base.v1
template_mode: strict
publisher: test
family: author-admin-key
version: 1
display_name: Author Admin Key
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
parameters:
  - name: bounded_admin_public_key
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
	if err := ValidateTemplateSpec(spec); err == nil || !strings.Contains(err.Error(), "framework-injected") {
		t.Fatalf("ValidateTemplateSpec() error = %v, want injected-parameter rejection", err)
	}
}

func TestComposedSchemaV1RejectsAuthorDeclaredAdminPublicKey(t *testing.T) {
	baseKeyType := "test.template-v1-author-admin-key-base.v1"
	registerTemplateTestBase(baseKeyType)
	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-v1-author-admin-key-base.v1
template_mode: strict
publisher: test
family: v1-author-admin-key
version: 1
display_name: V1 Author Admin Key
parameters:
  - name: bounded_admin_public_key
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
	if err := ValidateTemplateSpec(spec); err == nil || !strings.Contains(err.Error(), "framework-injected") {
		t.Fatalf("ValidateTemplateSpec() error = %v, want injected-parameter rejection", err)
	}
}

func TestTemplateSchemaSelectionAndStrictDecoding(t *testing.T) {
	registerTemplateTestBase("test.template-schema-selection-base.v1")
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
teal: int 1
`,
			want: "requires bounded",
		},
		{
			name: "unknown nested bounded field",
			yaml: "schema_version: 2\nbounded:\n  contract: bounded1\n  mystery: true\n",
			want: "field mystery not found",
		},
		{
			name: "unknown nested admin field",
			yaml: "schema_version: 2\nbounded:\n  admin_operations:\n    - kind: rekey\n      mystery: true\n",
			want: "field mystery not found",
		},
		{
			name: "unknown nested sentry field",
			yaml: "schema_version: 2\nbounded:\n  sentry:\n    contract: sentry1\n    mystery: true\n",
			want: "field mystery not found",
		},
		{
			name: "duplicate nested field",
			yaml: "schema_version: 2\nbounded:\n  contract: bounded1\n  contract: bounded1\n",
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
			yaml: "schema_version: 2\nbounded:\n  <<: {contract: bounded1}\n",
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

func TestComposedSchemaV2BuildsBoundedSentryProfile(t *testing.T) {
	RegisterBase(BaseRegistration{
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
family: bounded-sentry-test
version: 1
display_name: Bounded Sentry Test
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
  sentry:
    contract: sentry1
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
	if len(params) != 1 || params[0].Name != BoundedSentryPublicKeyParameter || params[0].MaxLength != boundedmeta.SentryPublicKeySizeV1*2 {
		t.Fatalf("CreationParams() = %#v, want injected sentry public key", params)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Sentry == nil || metadata.Sentry.Contract != boundedmeta.SentryContractV1 {
		t.Fatalf("BoundedAuthorizationMetadata() = %#v", metadata)
	}
	if got := metadata.ArgumentLayout; len(got) != 2 || got[1].Source != boundedmeta.ArgSourceSentry || got[1].Paths.Spend != boundedmeta.ArgRequired {
		t.Fatalf("ArgumentLayout = %#v, want base/sentry layout", got)
	}
}

func TestComposedSchemaV2RejectsInvalidBoundedSentry(t *testing.T) {
	RegisterBase(BaseRegistration{
		BaseKeyType:       "aplane.falcon1024.v1",
		FamilyName:        "falcon1024",
		Version:           1,
		Ops:               boundedTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
	registerTemplateTestBase("test.non-falcon-bounded-sentry.v1")
	base := `
schema_version: 2
template_type: composed
base_key_type: %s
template_mode: strict
publisher: test
family: invalid-bounded-sentry
version: 1
display_name: Invalid Bounded Sentry
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
  sentry:
    contract: %s
    required_on: [%s]
teal: |
  int 1
  assert
`
	tests := []struct {
		name, baseKeyType, contract, requiredOn, want string
	}{
		{name: "contract", baseKeyType: "aplane.falcon1024.v1", contract: "sentry2", requiredOn: "spend", want: "unsupported bounded sentry contract"},
		{name: "path", baseKeyType: "aplane.falcon1024.v1", contract: "sentry1", requiredOn: "spending_rekey", want: "exactly [spend]"},
		{name: "base", baseKeyType: "test.non-falcon-bounded-sentry.v1", contract: "sentry1", requiredOn: "spend", want: "requires base_key_type"},
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
	registerTemplateTestBase(baseKeyType)
	tests := []struct {
		name       string
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
		{
			name:    "runtime rekey mask mismatch",
			bounded: "  admin_operations:\n    - kind: rekey\n      authorization: spending_key\n      policy_gate: layer3\n  runtime_args:\n    - name: preimage\n      type: bytes\n      max_size: 64\n      required_on: [spend]\n",
			want:    "rekey requirement does not match",
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
			spec, err := ParseTemplateSpec([]byte(fmt.Sprintf(`schema_version: 2
template_type: composed
base_key_type: %s
template_mode: strict
publisher: test
family: bounded-args
version: 1
display_name: Bounded Args
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
%s%s%s
teal: |
  int 1
  assert
`, baseKeyType, tt.bounded, tt.parameters, tt.topLevel)))
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
	RegisterBase(BaseRegistration{
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
bounded:
  contract: bounded1
  spend_effects: [pay]
  admin_operations: []
teal: int 1
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := ValidateTemplateSpec(spec); err == nil || !strings.Contains(err.Error(), "bounded.max_fee is required") {
		t.Fatalf("ValidateTemplateSpec() error = %v, want explicit max_fee rejection", err)
	}
}

func TestValidateTemplateSpecRejectsNonRelocatableTEAL(t *testing.T) {
	registerTemplateTestBase("test.relocatable-base.v1")

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
	registerTemplateTestBase("test.relocatable-strict-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
template_type: composed
base_key_type: test.relocatable-strict-base.v1
template_mode: strict
publisher: test
family: relocatable-strict
version: 1
display_name: "Relocatable Strict"
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
	registerTemplateTestBase(baseKeyType)

	data := []byte(`
schema_version: 1
template_type: composed
base_key_type: test.template-existing-provider-base.v1
template_mode: generated
publisher: test
family: existing-provider
version: 1
display_name: "Existing Provider"
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

func TestBundledComposedTemplatesValidate(t *testing.T) {
	registerTemplateTestBase("aplane.falcon1024.v1")
	registerTemplateTestBase("aplane.ed25519.v1")

	paths := []string{
		"library/templates/aplane.falcon1024-allowlist-alock.v1.yaml",
		"library/templates/aplane.falcon1024-timelock.v1.yaml",
		"library/templates/aplane.falcon1024-allowlist.v1.yaml",
		"library/templates/aplane.falcon1024-allowlist.v2.yaml",
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", path))
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", path, err)
			}
			spec, err := ParseTemplateSpec(data)
			if err != nil {
				t.Fatalf("ParseTemplateSpec(%s) error = %v", path, err)
			}
			if err := ValidateTemplateSpec(spec); err != nil {
				t.Fatalf("ValidateTemplateSpec(%s) error = %v", path, err)
			}
			if spec.SchemaVersion != CurrentTemplateSchemaVersion || spec.Bounded == nil {
				t.Fatalf("%s must remain a schema-v%d bounded template", path, CurrentTemplateSchemaVersion)
			}
		})
	}
}

func TestSemanticFingerprintIncludesBaseKeyType(t *testing.T) {
	for _, keyType := range []string{"fingerprint-a-v1", "fingerprint-b-v1"} {
		RegisterBase(BaseRegistration{
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

func indentTEALForTest(teal string) string {
	var lines []string
	for _, line := range strings.Split(teal, "\n") {
		lines = append(lines, "  "+line)
	}
	return strings.Join(lines, "\n")
}
