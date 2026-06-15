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
family: template-base-whitelist
version: 1
display_name: "Template Base Whitelist"
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
	if provider.KeyType() != "test.template-base-whitelist.v1" {
		t.Fatalf("KeyType() = %q, want test.template-base-whitelist.v1", provider.KeyType())
	}
}

func TestNewProviderFromTemplateSpecUsesDerivationVersion(t *testing.T) {
	registerTemplateTestBase("test.template-derivation-base.v1")

	spec, err := ParseTemplateSpec([]byte(`
schema_version: 1
derivation_version: 2
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
	if got := provider.fingerprintSaltStyle(); got != string(lsigsalt.StyleTrailingBytecblock) {
		t.Fatalf("fingerprintSaltStyle() = %q, want %q", got, lsigsalt.StyleTrailingBytecblock)
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

	paths := []string{
		"library/templates/aplane.falcon1024-hashlock.v1.yaml",
		"library/templates/aplane.falcon1024-timelock.v1.yaml",
		"library/templates/aplane.falcon1024-whitelist.v1.yaml",
		"library/templates/aplane.falcon1024-whitelist.v2.yaml",
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
