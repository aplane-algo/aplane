// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package template

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

func TestLoadTemplatesFromFS_Empty(t *testing.T) {
	// When no embedded templates, LoadTemplatesFromFS should return empty slice (not error)
	providers, err := LoadTemplatesFromFS()
	if err != nil {
		t.Fatalf("LoadTemplatesFromFS failed: %v", err)
	}

	// With no embedded templates, this should be empty or nil
	t.Logf("Loaded %d embedded templates", len(providers))
}

func TestParseTemplateSpec(t *testing.T) {
	yamlData := []byte(`
schema_version: 1
family: falcon1024-test
version: 1
display_name: "Falcon Test"
description: "Test template"
parameters:
  - name: hash
    type: bytes
    required: true
    max_length: 64
    label: "SHA256 Hash"
runtime_args:
  - name: preimage
    type: bytes
    label: "Secret Preimage"
teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  arg 1
  sha256
  byte @hash
  ==
  assert
`)

	spec, err := ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec failed: %v", err)
	}

	if spec.Family != "falcon1024-test" {
		t.Errorf("Expected family falcon1024-test, got %s", spec.Family)
	}
	if spec.Version != 1 {
		t.Errorf("Expected version 1, got %d", spec.Version)
	}
	if spec.DisplayName != "Falcon Test" {
		t.Errorf("Expected display_name 'Falcon Test', got %s", spec.DisplayName)
	}
	if len(spec.Parameters) != 1 {
		t.Errorf("Expected 1 parameter, got %d", len(spec.Parameters))
	}
	if len(spec.RuntimeArgs) != 1 {
		t.Errorf("Expected 1 runtime_arg, got %d", len(spec.RuntimeArgs))
	}
	if spec.KeyType() != "falcon1024-test-v1" {
		t.Errorf("Expected keyType falcon1024-test-v1, got %s", spec.KeyType())
	}
}

func TestValidateSpec(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid spec",
			yaml: `
schema_version: 1
family: falcon1024-test
version: 1
display_name: "Falcon Test"
description: "Test"
parameters:
  - name: hash
    type: bytes
    required: true
    max_length: 64
    label: "Hash"
teal: |
  arg 1
  sha256
  byte @hash
  ==
  assert
`,
			wantErr: false,
		},
		{
			name: "missing family",
			yaml: `
schema_version: 1
version: 1
display_name: "Test"
teal: |
  int 1
`,
			wantErr: true,
			errMsg:  "family is required",
		},
		{
			name: "missing teal",
			yaml: `
schema_version: 1
family: falcon1024-test
version: 1
display_name: "Test"
`,
			wantErr: true,
			errMsg:  "teal is required",
		},
		{
			name: "undefined parameter in teal",
			yaml: `
schema_version: 1
family: falcon1024-test
version: 1
display_name: "Test"
teal: |
  byte @nonexistent
`,
			wantErr: true,
			errMsg:  "undefined parameters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseTemplateSpec([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("ParseTemplateSpec failed: %v", err)
			}

			err = ValidateSpec(spec)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCreateProviderFromSpec(t *testing.T) {
	yamlData := []byte(`
schema_version: 1
family: falcon1024-timelock
version: 1
display_name: "Falcon Timelock"
description: "Falcon with timelock"
parameters:
  - name: unlock_round
    type: uint64
    required: true
    max_length: 20
    label: "Unlock Round"
teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  txn CloseRemainderTo
  global ZeroAddress
  ==
  assert
  txn FirstValid
  int @unlock_round
  >=
  assert
`)

	spec, err := ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec failed: %v", err)
	}

	provider, err := CreateProviderFromSpec(spec)
	if err != nil {
		t.Fatalf("CreateProviderFromSpec failed: %v", err)
	}

	if provider.KeyType() != "falcon1024-timelock-v1" {
		t.Errorf("Expected keyType falcon1024-timelock-v1, got %s", provider.KeyType())
	}
	if provider.DisplayName() != "Falcon Timelock" {
		t.Errorf("Expected displayName 'Falcon Timelock', got %s", provider.DisplayName())
	}

	// Check creation params - timelock adds unlock_round
	params := provider.CreationParams()
	fmt.Printf("CreationParams (%d):\n", len(params))
	for _, p := range params {
		fmt.Printf("  - %s (%s)\n", p.Name, p.Type)
	}
	if len(params) != 1 {
		t.Errorf("Expected 1 creation param (unlock_round), got %d", len(params))
	}
}

func TestRegisterTemplates_NoEmbedded(t *testing.T) {
	// RegisterTemplates should not fail when no templates are embedded
	RegisterTemplates()

	// With no embedded templates, nothing should be registered via this path
	t.Log("RegisterTemplates completed without error")
}

func TestRegisterProvider(t *testing.T) {
	yamlData := []byte(`
schema_version: 1
family: falcon1024-regtest
version: 1
display_name: "Falcon Register Test"
description: "Test registration"
parameters:
  - name: hash
    type: bytes
    required: true
    max_length: 64
    label: "Hash"
teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  txn CloseRemainderTo
  global ZeroAddress
  ==
  assert
  arg 1
  sha256
  byte @hash
  ==
  assert
`)

	spec, err := ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec failed: %v", err)
	}

	provider, err := CreateProviderFromSpec(spec)
	if err != nil {
		t.Fatalf("CreateProviderFromSpec failed: %v", err)
	}

	// Register it
	registerProvider(provider)

	// Check logicsigdsa registry
	keyType := "falcon1024-regtest-v1"
	dsa := logicsigdsa.Get(keyType)
	if dsa == nil {
		t.Fatalf("%s not registered in logicsigdsa", keyType)
	}

	t.Logf("Successfully registered %s", keyType)
}
