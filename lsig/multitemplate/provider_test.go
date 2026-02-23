// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package multitemplate

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/templatestore"
)

// testBase returns a BaseTemplateSpec with common test values.
// Use for tests that don't care about specific base field values.
func testBase() templatestore.BaseTemplateSpec {
	return templatestore.BaseTemplateSpec{
		Family:      "test",
		Version:     1,
		DisplayName: "Test",
	}
}

func TestSubstituteVariables(t *testing.T) {
	spec := &TemplateSpec{
		Parameters: []ParameterSpec{
			{Name: "recipient", Type: "address"},
			{Name: "unlock_round", Type: "uint64"},
			{Name: "hash", Type: "bytes"},
		},
	}

	tests := []struct {
		name     string
		teal     string
		params   map[string]string
		expected string
		wantErr  bool
	}{
		{
			name: "address and uint64",
			teal: "addr @recipient\nint @unlock_round",
			params: map[string]string{
				"recipient":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
				"unlock_round": "12345",
			},
			expected: "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\nint 12345",
			wantErr:  false,
		},
		{
			name: "bytes adds 0x prefix",
			teal: "byte @hash",
			params: map[string]string{
				"hash": "deadbeef",
			},
			expected: "byte 0xdeadbeef",
			wantErr:  false,
		},
		{
			name: "bytes with existing 0x prefix normalized",
			teal: "byte @hash",
			params: map[string]string{
				"hash": "0xdeadbeef",
			},
			expected: "byte 0xdeadbeef",
			wantErr:  false,
		},
		{
			name: "bytes with existing 0X prefix normalized",
			teal: "byte @hash",
			params: map[string]string{
				"hash": "0XDEADBEEF",
			},
			expected: "byte 0xDEADBEEF",
			wantErr:  false,
		},
		{
			name:    "missing variable",
			teal:    "int @unknown",
			params:  map[string]string{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := SubstituteVariables(tc.teal, tc.params, spec)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestValidateParameterValue(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		paramType  string
		byteLength int
		wantErr    bool
	}{
		// Address tests
		{
			name:      "valid address",
			value:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			paramType: "address",
			wantErr:   false,
		},
		{
			name:      "invalid address length",
			value:     "INVALID",
			paramType: "address",
			wantErr:   true,
		},

		// Uint64 tests
		{
			name:      "valid uint64",
			value:     "12345",
			paramType: "uint64",
			wantErr:   false,
		},
		{
			name:      "valid uint64 zero",
			value:     "0",
			paramType: "uint64",
			wantErr:   false,
		},
		{
			name:      "invalid uint64 negative",
			value:     "-1",
			paramType: "uint64",
			wantErr:   true,
		},
		{
			name:      "invalid uint64 hex",
			value:     "0x123",
			paramType: "uint64",
			wantErr:   true,
		},
		{
			name:      "invalid uint64 letters",
			value:     "abc",
			paramType: "uint64",
			wantErr:   true,
		},

		// Bytes tests
		{
			name:      "valid bytes",
			value:     "deadbeef",
			paramType: "bytes",
			wantErr:   false,
		},
		{
			name:       "valid bytes with length",
			value:      "deadbeefdeadbeef",
			paramType:  "bytes",
			byteLength: 8,
			wantErr:    false,
		},
		{
			name:       "invalid bytes wrong length",
			value:      "deadbeef",
			paramType:  "bytes",
			byteLength: 8,
			wantErr:    true,
		},
		{
			name:      "invalid bytes not hex",
			value:     "zzzz",
			paramType: "bytes",
			wantErr:   true,
		},
		{
			name:      "valid bytes with 0x prefix",
			value:     "0xdeadbeef",
			paramType: "bytes",
			wantErr:   false,
		},
		{
			name:      "valid bytes with 0X prefix",
			value:     "0Xdeadbeef",
			paramType: "bytes",
			wantErr:   false,
		},
		{
			name:      "invalid bytes just 0x prefix",
			value:     "0x",
			paramType: "bytes",
			wantErr:   true,
		},

		// Unknown type
		{
			name:      "unknown type",
			value:     "test",
			paramType: "string",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateParameterValue(tc.value, tc.paramType, tc.byteLength)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateParametersUnknown(t *testing.T) {
	spec := &TemplateSpec{
		Parameters: []ParameterSpec{
			{Name: "recipient", Type: "address", Required: true},
		},
	}

	// Valid parameter
	err := ValidateParameters(map[string]string{
		"recipient": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}, spec)
	if err != nil {
		t.Errorf("unexpected error for valid params: %v", err)
	}

	// Unknown parameter (typo)
	err = ValidateParameters(map[string]string{
		"recepient": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}, spec)
	if err == nil {
		t.Error("expected error for unknown parameter 'recepient', got nil")
	}
	if !strings.Contains(err.Error(), "unknown parameter") {
		t.Errorf("expected 'unknown parameter' error, got: %v", err)
	}
}

func TestValidateSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    *TemplateSpec
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid spec",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "addr", Type: "address"},
				},
				TEAL: "addr @addr\nreturn",
			},
			wantErr: false,
		},
		{
			name: "missing family",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					Version:     1,
					DisplayName: "Test",
				},
				TEAL: "return",
			},
			wantErr: true,
			errMsg:  "family is required",
		},
		{
			name: "invalid version",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					Family:      "test",
					DisplayName: "Test",
				},
				TEAL: "return",
			},
			wantErr: true,
			errMsg:  "version must be >= 1",
		},
		{
			name: "invalid parameter type",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "foo", Type: "string"},
				},
				TEAL: "return",
			},
			wantErr: true,
			errMsg:  "invalid type",
		},
		{
			name: "undefined variable in TEAL",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters:       []ParameterSpec{},
				TEAL:             "int @undefined_var\nreturn",
			},
			wantErr: true,
			errMsg:  "undefined parameters",
		},
		{
			name: "duplicate parameter name",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "addr", Type: "address"},
					{Name: "addr", Type: "uint64"},
				},
				TEAL: "addr @addr\nreturn",
			},
			wantErr: true,
			errMsg:  "duplicate parameter name",
		},
		{
			name: "future schema version rejected",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					SchemaVersion: 999,
					Family:        "test",
					Version:       1,
					DisplayName:   "Test",
				},
				TEAL: "return",
			},
			wantErr: true,
			errMsg:  "newer than supported",
		},
		{
			name: "min/max only for uint64",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "addr", Type: "address", Min: ptrUint64(1)},
				},
				TEAL: "addr @addr\nreturn",
			},
			wantErr: true,
			errMsg:  "min/max constraints only valid for uint64",
		},
		{
			name: "min greater than max",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "val", Type: "uint64", Min: ptrUint64(100), Max: ptrUint64(50)},
				},
				TEAL: "int @val\nreturn",
			},
			wantErr: true,
			errMsg:  "min (100) cannot be greater than max (50)",
		},
		{
			name: "valid min/max constraints",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "val", Type: "uint64", Min: ptrUint64(1), Max: ptrUint64(100)},
				},
				TEAL: "int @val\nreturn",
			},
			wantErr: false,
		},
		{
			name: "invalid default value",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "val", Type: "uint64", Default: "notanumber"},
				},
				TEAL: "int @val\nreturn",
			},
			wantErr: true,
			errMsg:  "invalid default",
		},
		{
			name: "default violates min constraint",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "val", Type: "uint64", Min: ptrUint64(10), Default: "5"},
				},
				TEAL: "int @val\nreturn",
			},
			wantErr: true,
			errMsg:  "invalid default",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestYAMLTemplateInterface(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: templatestore.BaseTemplateSpec{
			Family:       "test",
			Version:      1,
			DisplayName:  "Test Template",
			Description:  "A test template",
			DisplayColor: "32",
		},
		Parameters: []ParameterSpec{
			{
				Name:        "recipient",
				Label:       "Recipient",
				Description: "The recipient address",
				Type:        "address",
				Required:    true,
			},
			{
				Name:        "amount",
				Label:       "Amount",
				Description: "The amount",
				Type:        "uint64",
				Required:    true,
			},
		},
		TEAL: "addr @recipient\nint @amount\nreturn",
	}

	tmpl := NewYAMLTemplate(spec)

	// Test identity methods
	if tmpl.KeyType() != "test-v1" {
		t.Errorf("expected KeyType test-v1, got %s", tmpl.KeyType())
	}
	if tmpl.Family() != "test" {
		t.Errorf("expected Family test, got %s", tmpl.Family())
	}
	if tmpl.Version() != 1 {
		t.Errorf("expected Version 1, got %d", tmpl.Version())
	}

	// Test display methods
	if tmpl.DisplayName() != "Test Template" {
		t.Errorf("expected DisplayName 'Test Template', got %s", tmpl.DisplayName())
	}
	if tmpl.Description() != "A test template" {
		t.Errorf("expected Description 'A test template', got %s", tmpl.Description())
	}
	if tmpl.DisplayColor() != "32" {
		t.Errorf("expected DisplayColor 32, got %s", tmpl.DisplayColor())
	}

	// Test Parameters
	params := tmpl.CreationParams()
	if len(params) != 2 {
		t.Errorf("expected 2 parameters, got %d", len(params))
	}

	// Test RuntimeArgs (should be nil)
	if args := tmpl.RuntimeArgs(); args != nil {
		t.Errorf("expected RuntimeArgs nil, got %v", args)
	}
}

func TestYAMLTemplateGenerateTEAL(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		Parameters: []ParameterSpec{
			{Name: "recipient", Type: "address", Required: true},
			{Name: "unlock_round", Type: "uint64", Required: true},
		},
		TEAL: "addr @recipient\nint @unlock_round\nreturn",
	}

	tmpl := NewYAMLTemplate(spec)

	// Test successful generation
	params := map[string]string{
		"recipient":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"unlock_round": "12345",
	}

	teal, err := tmpl.GenerateTEAL(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\nint 12345\nreturn"
	if teal != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, teal)
	}

	// Test missing required parameter
	_, err = tmpl.GenerateTEAL(map[string]string{"recipient": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"})
	if err == nil {
		t.Error("expected error for missing required parameter")
	}
}

func TestLoadTemplatesFromFS(t *testing.T) {
	templates, err := LoadTemplatesFromFS()
	if err != nil {
		t.Fatalf("failed to load templates: %v", err)
	}

	// No embedded YAML templates by default (reference templates are in examples/templates/)
	if len(templates) != 0 {
		t.Errorf("expected 0 embedded templates, got %d", len(templates))
	}
}

func TestDefaultDisplayColor(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL:             "return",
		// DisplayColor not set in testBase()
	}

	tmpl := NewYAMLTemplate(spec)

	if tmpl.DisplayColor() != "35" {
		t.Errorf("expected default color '35', got %q", tmpl.DisplayColor())
	}
}

func TestValidateUint64Constraints(t *testing.T) {
	min10 := uint64(10)
	max100 := uint64(100)

	tests := []struct {
		name    string
		value   string
		min     *uint64
		max     *uint64
		wantErr bool
	}{
		{"within range", "50", &min10, &max100, false},
		{"at min", "10", &min10, &max100, false},
		{"at max", "100", &min10, &max100, false},
		{"below min", "5", &min10, nil, true},
		{"above max", "150", nil, &max100, true},
		{"no constraints", "999", nil, nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUint64Constraints(tc.value, tc.min, tc.max)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParametersWithConstraints(t *testing.T) {
	min1 := uint64(1)
	max1000 := uint64(1000)
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		Parameters: []ParameterSpec{
			{
				Name:        "amount",
				Label:       "Amount",
				Type:        "uint64",
				Required:    true,
				Min:         &min1,
				Max:         &max1000,
				Example:     "500",
				Placeholder: "Enter amount",
				Default:     "100",
			},
		},
		TEAL: "int @amount\nreturn",
	}

	tmpl := NewYAMLTemplate(spec)
	params := tmpl.CreationParams()

	if len(params) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(params))
	}

	p := params[0]
	if p.Example != "500" {
		t.Errorf("expected Example '500', got %q", p.Example)
	}
	if p.Placeholder != "Enter amount" {
		t.Errorf("expected Placeholder 'Enter amount', got %q", p.Placeholder)
	}
	if p.Min == nil || *p.Min != 1 {
		t.Error("expected Min to be 1")
	}
	if p.Max == nil || *p.Max != 1000 {
		t.Error("expected Max to be 1000")
	}
	if p.Default != "100" {
		t.Errorf("expected Default '100', got %q", p.Default)
	}
}

func TestValidateParametersWithMinMax(t *testing.T) {
	min10 := uint64(10)
	max100 := uint64(100)
	spec := &TemplateSpec{
		Parameters: []ParameterSpec{
			{Name: "val", Type: "uint64", Required: true, Min: &min10, Max: &max100},
		},
	}

	// Valid value
	err := ValidateParameters(map[string]string{"val": "50"}, spec)
	if err != nil {
		t.Errorf("unexpected error for valid value: %v", err)
	}

	// Below min
	err = ValidateParameters(map[string]string{"val": "5"}, spec)
	if err == nil {
		t.Error("expected error for value below min")
	}

	// Above max
	err = ValidateParameters(map[string]string{"val": "150"}, spec)
	if err == nil {
		t.Error("expected error for value above max")
	}
}

// ptrUint64 returns a pointer to a uint64 value (helper for tests)
func ptrUint64(v uint64) *uint64 {
	return &v
}

func TestRuntimeArgs(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL:             "return",
		RuntimeArgs: []RuntimeArgSpec{
			{
				Name:        "preimage",
				Label:       "Preimage",
				Description: "The secret",
				Type:        "bytes",
				ByteLength:  32,
			},
		},
	}

	tmpl := NewYAMLTemplate(spec)
	args := tmpl.RuntimeArgs()

	if len(args) != 1 {
		t.Fatalf("expected 1 runtime arg, got %d", len(args))
	}

	arg := args[0]
	if arg.Name != "preimage" {
		t.Errorf("expected name 'preimage', got %q", arg.Name)
	}
	if arg.Label != "Preimage" {
		t.Errorf("expected label 'Preimage', got %q", arg.Label)
	}
	if arg.Type != "bytes" {
		t.Errorf("expected type 'bytes', got %q", arg.Type)
	}
	if arg.ByteLength != 32 {
		t.Errorf("expected ByteLength 32, got %d", arg.ByteLength)
	}
}

func TestRuntimeArgsValidation(t *testing.T) {
	tests := []struct {
		name    string
		spec    *TemplateSpec
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid runtime arg",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             "return",
				RuntimeArgs: []RuntimeArgSpec{
					{Name: "preimage", Type: "bytes"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty runtime arg name",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             "return",
				RuntimeArgs: []RuntimeArgSpec{
					{Name: "", Type: "bytes"},
				},
			},
			wantErr: true,
			errMsg:  "runtime_arg name is required",
		},
		{
			name: "duplicate runtime arg name",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             "return",
				RuntimeArgs: []RuntimeArgSpec{
					{Name: "preimage", Type: "bytes"},
					{Name: "preimage", Type: "string"},
				},
			},
			wantErr: true,
			errMsg:  "duplicate runtime_arg name",
		},
		{
			name: "invalid runtime arg type",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             "return",
				RuntimeArgs: []RuntimeArgSpec{
					{Name: "arg", Type: "invalid"},
				},
			},
			wantErr: true,
			errMsg:  "invalid type",
		},
		{
			name: "string type is valid",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             "return",
				RuntimeArgs: []RuntimeArgSpec{
					{Name: "password", Type: "string"},
				},
			},
			wantErr: false,
		},
		{
			name: "uint64 type is valid",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             "return",
				RuntimeArgs: []RuntimeArgSpec{
					{Name: "nonce", Type: "uint64"},
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errMsg)
				} else if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error containing %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
