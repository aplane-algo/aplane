// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package generictemplate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/internal/templatestore"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// testBase returns a BaseTemplateSpec with common test values and explicit
// pushbytes derivation for tests that exercise the historical salted path.
func testBase() templatestore.BaseTemplateSpec {
	derivationVersion := templatestore.DerivationVersionPushbytes
	return templatestore.BaseTemplateSpec{
		DerivationVersion: &derivationVersion,
		Publisher:         "test",
		Family:            "test",
		Version:           1,
		DisplayName:       "Test",
	}
}

func testBaseWithoutDerivationVersion() templatestore.BaseTemplateSpec {
	base := testBase()
	base.DerivationVersion = nil
	return base
}

func testBaseWithDerivationVersion(version int) templatestore.BaseTemplateSpec {
	base := testBase()
	base.DerivationVersion = &version
	return base
}

type compileMockTransport struct {
	bytecode []byte
}

func (m compileMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2/teal/compile" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"unexpected request"}`)),
			Request:    req,
		}, nil
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		return nil, err
	}
	body := `{"result":"` + base64.StdEncoding.EncodeToString(m.bytecode) + `","hash":"ignored-unsalted-hash"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
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
			name:      "valid string",
			value:     "test",
			paramType: "string",
			wantErr:   false,
		},
		{
			name:      "valid select",
			value:     "choice",
			paramType: "select",
			wantErr:   false,
		},
		{
			name:      "unknown type",
			value:     "test",
			paramType: "unknown",
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

func TestValidateParametersAddressList(t *testing.T) {
	spec := &TemplateSpec{
		Parameters: []ParameterSpec{
			{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 3},
		},
	}

	err := ValidateParameters(map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ, AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI",
	}, spec)
	if err != nil {
		t.Fatalf("ValidateParameters(valid address[]) error = %v", err)
	}

	err = ValidateParameters(map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}, spec)
	if err == nil {
		t.Fatal("ValidateParameters(duplicate address[]) error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("ValidateParameters(duplicate address[]) error = %v, want duplicate rejection", err)
	}
}

func TestYAMLTemplateAddressListCanonicalizesTEALByDefault(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		Parameters: []ParameterSpec{{
			Name:     "recipients",
			Type:     "address[]",
			Required: true,
			MinItems: 1,
			MaxItems: 3,
		}},
		TEAL: "{{range @recipients}}addr {{.}}\n{{end}}return",
	}
	tmpl := NewYAMLTemplate(spec)

	addrA := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addrB := "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI"

	first, err := tmpl.GenerateTEAL(map[string]string{"recipients": addrA + "," + addrB})
	if err != nil {
		t.Fatalf("GenerateTEAL(first) error = %v", err)
	}
	second, err := tmpl.GenerateTEAL(map[string]string{"recipients": addrB + "," + addrA})
	if err != nil {
		t.Fatalf("GenerateTEAL(second) error = %v", err)
	}

	if first != second {
		t.Fatalf("GenerateTEAL differs for reordered whitelist:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestYAMLTemplateCompileUsesCallerContext(t *testing.T) {
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL:             "int 1",
	})
	client, err := algod.MakeClient("http://127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = tmpl.Compile(ctx, nil, client)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Compile() error = %v, want context canceled", err)
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

func TestParameterSpecToParameterDefsPreservesInputModes(t *testing.T) {
	defs := ParameterSpecToParameterDefs([]ParameterSpec{{
		Name:      "hash",
		Type:      "bytes",
		Required:  true,
		MaxLength: 64,
		InputModes: []InputModeSpec{
			{Name: "preimage", Label: "Preimage", Transform: "sha256", InputType: "string"},
			{Name: "hash", Label: "SHA256 Hash"},
		},
	}})

	if len(defs) != 1 || len(defs[0].InputModes) != 2 {
		t.Fatalf("defs = %#v, want two input modes", defs)
	}
	want := lsigprovider.InputMode{Name: "preimage", Label: "Preimage", Transform: "sha256", InputType: "string"}
	if defs[0].InputModes[0] != want {
		t.Fatalf("first input mode = %#v, want %#v", defs[0].InputModes[0], want)
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
			name: "valid address list spec",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30},
				},
				TEAL: "{{range @recipients}}\naddr {{.}}\n{{end}}\nreturn",
			},
			wantErr: false,
		},
		{
			name: "generic rejects base key type",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					TemplateType: "generic",
					BaseKeyType:  "aplane.falcon1024.v1",
					Publisher:    "test",
					Family:       "test",
					Version:      1,
					DisplayName:  "Test",
				},
				TEAL: "return",
			},
			wantErr: true,
			errMsg:  "base_key_type must not be set for generic templates",
		},
		{
			name: "missing family",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					Publisher:   "test",
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
					Publisher:   "test",
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
			name: "invalid input mode transform",
			spec: &TemplateSpec{
				BaseTemplateSpec: testBase(),
				Parameters: []ParameterSpec{
					{
						Name:      "hash",
						Type:      "bytes",
						Required:  true,
						MaxLength: 64,
						InputModes: []InputModeSpec{
							{Name: "preimage", Transform: "md5"},
						},
					},
				},
				TEAL: "return",
			},
			wantErr: true,
			errMsg:  "unsupported transform",
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
					Publisher:     "test",
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
			name: "valid schema v1 strict spec",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					SchemaVersion: 1,
					Publisher:     "test",
					Family:        "test",
					Version:       1,
					DisplayName:   "Test",
				},
				TemplateMode: TemplateModeStrict,
				Parameters: []ParameterSpec{
					{Name: "unlock_round", Type: "uint64", Required: true},
				},
				TemplateVariables: []tealtemplate.TemplateVariable{
					{
						Name:      "unlock_round",
						Source:    tealtemplate.SourceParameter,
						Parameter: "unlock_round",
						Type:      "uint64",
						Constant:  tealtemplate.ConstantInt,
					},
				},
				TEAL: "txn FirstValid\n$unlock_round\n>=\nassert",
			},
			wantErr: false,
		},
		{
			name: "schema v1 strict rejects legacy scalar substitution",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					SchemaVersion: 1,
					Publisher:     "test",
					Family:        "test",
					Version:       1,
					DisplayName:   "Test",
				},
				TemplateMode: TemplateModeStrict,
				Parameters: []ParameterSpec{
					{Name: "unlock_round", Type: "uint64", Required: true},
				},
				TemplateVariables: []tealtemplate.TemplateVariable{
					{
						Name:      "unlock_round",
						Source:    tealtemplate.SourceParameter,
						Parameter: "unlock_round",
						Type:      "uint64",
						Constant:  tealtemplate.ConstantInt,
					},
				},
				TEAL: "int @unlock_round",
			},
			wantErr: true,
			errMsg:  "legacy scalar substitution",
		},
		{
			name: "schema v1 strict validates variable parameter mapping",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					SchemaVersion: 1,
					Publisher:     "test",
					Family:        "test",
					Version:       1,
					DisplayName:   "Test",
				},
				TemplateMode: TemplateModeStrict,
				Parameters: []ParameterSpec{
					{Name: "unlock_round", Type: "uint64", Required: true},
				},
				TemplateVariables: []tealtemplate.TemplateVariable{
					{
						Name:      "unlock_round",
						Source:    tealtemplate.SourceParameter,
						Parameter: "missing",
						Type:      "uint64",
						Constant:  tealtemplate.ConstantInt,
					},
				},
				TEAL: "$unlock_round",
			},
			wantErr: true,
			errMsg:  "unknown parameter",
		},
		{
			name: "schema v1 generated rejects unsupported template syntax",
			spec: &TemplateSpec{
				BaseTemplateSpec: templatestore.BaseTemplateSpec{
					SchemaVersion: 1,
					Publisher:     "test",
					Family:        "test",
					Version:       1,
					DisplayName:   "Test",
				},
				TemplateMode: TemplateModeGenerated,
				Parameters: []ParameterSpec{
					{Name: "recipients", Type: "address[]", Required: true},
				},
				TEAL: "{{len @recipients}}",
			},
			wantErr: true,
			errMsg:  "unsupported",
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
			Publisher:    "test",
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
	if tmpl.KeyType() != "test.test.v1" {
		t.Errorf("expected KeyType test.test.v1, got %s", tmpl.KeyType())
	}
	if tmpl.RoutingFamily() != "test" {
		t.Errorf("expected Family test, got %s", tmpl.RoutingFamily())
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

	expected := "// Salt byte, patched post-compilation to avoid ed25519-curve addresses.\nbyte 0x" + lsigsalt.PushbytesSaltMarkerHex(0) + "\npop\n\naddr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\nint 12345\nreturn"
	if teal != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, teal)
	}

	// Test missing required parameter
	_, err = tmpl.GenerateTEAL(map[string]string{"recipient": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"})
	if err == nil {
		t.Error("expected error for missing required parameter")
	}
}

func TestYAMLTemplateGenerateTEALOmittedDerivationIsUnsalted(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBaseWithoutDerivationVersion(),
		Parameters: []ParameterSpec{
			{Name: "recipient", Type: "address", Required: true},
			{Name: "unlock_round", Type: "uint64", Required: true},
		},
		TEAL: "addr @recipient\nint @unlock_round\nreturn",
	}

	tmpl := NewYAMLTemplate(spec)
	teal, err := tmpl.GenerateTEAL(map[string]string{
		"recipient":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"unlock_round": "12345",
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	expected := "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\nint 12345\nreturn"
	if teal != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, teal)
	}
}

func TestYAMLTemplateGenerateTEALTrailingBytecblockDerivation(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBaseWithDerivationVersion(templatestore.DerivationVersionTrailingBytecblock),
		Parameters: []ParameterSpec{
			{Name: "recipient", Type: "address", Required: true},
			{Name: "unlock_round", Type: "uint64", Required: true},
		},
		TEAL: "addr @recipient\nint @unlock_round\nreturn",
	}

	tmpl := NewYAMLTemplate(spec)
	teal, err := tmpl.GenerateTEAL(map[string]string{
		"recipient":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"unlock_round": "12345",
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	expected := "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\nint 12345\nreturn\n\n// Salt byte, patched post-compilation to avoid ed25519-curve addresses.\nbytecblock 0x00"
	if teal != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, teal)
	}
}

func TestYAMLTemplateGenerateTEALTrailingBytecblockRequiresExit(t *testing.T) {
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBaseWithDerivationVersion(templatestore.DerivationVersionTrailingBytecblock),
		TEAL:             "int 1",
	})

	_, err := tmpl.GenerateTEAL(nil)
	if err == nil {
		t.Fatal("GenerateTEAL() error = nil, want final exit rejection")
	}
	if !strings.Contains(err.Error(), "requires template TEAL to end with return or err") {
		t.Fatalf("GenerateTEAL() error = %v, want final exit rejection", err)
	}
}

func TestYAMLTemplateGenerateTEALStrict(t *testing.T) {
	derivationVersion := templatestore.DerivationVersionPushbytes
	spec := &TemplateSpec{
		BaseTemplateSpec: templatestore.BaseTemplateSpec{
			SchemaVersion:     1,
			DerivationVersion: &derivationVersion,
			Publisher:         "test",
			Family:            "strict",
			Version:           1,
			DisplayName:       "Strict",
		},
		TemplateMode: TemplateModeStrict,
		Parameters: []ParameterSpec{
			{Name: "unlock_round", Type: "uint64", Required: true},
			{Name: "hash", Type: "bytes", Required: true, MaxLength: 4},
		},
		TemplateVariables: []tealtemplate.TemplateVariable{
			{
				Name:      "unlock_round",
				Source:    tealtemplate.SourceParameter,
				Parameter: "unlock_round",
				Type:      "uint64",
				Constant:  tealtemplate.ConstantInt,
			},
			{
				Name:      "hash",
				Source:    tealtemplate.SourceParameter,
				Parameter: "hash",
				Type:      "bytes",
				Constant:  tealtemplate.ConstantByte,
			},
		},
		TEAL: `#pragma version 10
txn FirstValid
$unlock_round
>=
assert
arg 0
sha256
$hash
==
assert`,
	}

	tmpl := NewYAMLTemplate(spec)
	teal, err := tmpl.GenerateTEAL(map[string]string{
		"unlock_round": "00042",
		"hash":         "0XABCD",
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	want := `#pragma version 10
intcblock 42
bytecblock 0xabcd

// Salt byte, patched post-compilation to avoid ed25519-curve addresses.
byte 0x` + lsigsalt.PushbytesSaltMarkerHex(0) + `
pop

txn FirstValid
intc_0
>=
assert
arg 0
sha256
bytec_0
==
assert`
	if teal != want {
		t.Fatalf("GenerateTEAL() =\n%s\nwant\n%s", teal, want)
	}
}

func TestYAMLTemplateCompileWithSalt(t *testing.T) {
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL: `#pragma version 10
int 1
	return`,
	})
	compiled := compiledPushbytesSaltBytecode(0)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}

	want, err := lsigsalt.FindOffCurve(compiled, lsigsalt.PushbytesLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	got, err := tmpl.CompileWithSalt(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("CompileWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("CompileWithSalt() = %+v, want %+v", got, want)
	}
	if lsigsalt.IsOnCurve(got.Address) {
		t.Fatal("CompileWithSalt() returned on-curve address")
	}

	bytecode, address, err := tmpl.Compile(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if string(bytecode) != string(want.Bytecode) || address != want.Address.String() {
		t.Fatalf("Compile() = (%x, %s), want (%x, %s)", bytecode, address, want.Bytecode, want.Address)
	}
}

func TestYAMLTemplateCompileWithSaltOmittedDerivationUsesUnmodifiedBytecode(t *testing.T) {
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBaseWithoutDerivationVersion(),
		TEAL: `#pragma version 10
int 1
return`,
	})
	compiled := unsaltedOffCurveBytecodeForTest(t)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}

	want, err := lsigsalt.UseUnmodifiedOffCurve(compiled)
	if err != nil {
		t.Fatalf("UseUnmodifiedOffCurve() error = %v", err)
	}
	got, err := tmpl.CompileWithSalt(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("CompileWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || !bytes.Equal(got.Bytecode, want.Bytecode) {
		t.Fatalf("CompileWithSalt() = %+v, want %+v", got, want)
	}
}

func TestYAMLTemplateCompileWithSaltTrailingBytecblock(t *testing.T) {
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBaseWithDerivationVersion(templatestore.DerivationVersionTrailingBytecblock),
		TEAL: `#pragma version 10
int 1
return`,
	})
	compiled := compiledTrailingBytecblockSaltBytecode(0)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}

	want, err := lsigsalt.FindOffCurve(compiled, lsigsalt.TrailingBytecblockLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	got, err := tmpl.CompileWithSalt(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("CompileWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("CompileWithSalt() = %+v, want %+v", got, want)
	}
}

func TestYAMLTemplateSaltDerivationGolden(t *testing.T) {
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL: `#pragma version 10
int 1
return`,
	})
	teal, err := tmpl.GenerateTEAL(nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	compiled := compiledPushbytesSaltBytecode(0)
	if _, err := lsigsalt.PushbytesMarkerLocator(compiled); err != nil {
		t.Fatalf("PushbytesMarkerLocator() error = %v", err)
	}
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	salted, err := tmpl.CompileWithSalt(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("CompileWithSalt() error = %v", err)
	}
	if lsigsalt.IsOnCurve(salted.Address) {
		t.Fatalf("CompileWithSalt() returned on-curve address %s", salted.Address.String())
	}

	assertGolden(t, "teal hash", sha256Hex([]byte(teal)), "f006aa5b2397340bf36f6eb2842ec5ff501485d5c2d00f7f6ee3829ffdd3bc75")
	assertGolden(t, "pre-salt bytecode hash", sha256Hex(compiled), "920691094839c8db0b2ca0b6c11299fb56594ba8fe86d6aa883b7eb534d0611e")
	assertGolden(t, "salt counter", hex.EncodeToString([]byte{salted.Counter}), "01")
	assertGolden(t, "derived address", salted.Address.String(), "EZJ3DQPMCFPZIZVAR6ZUQRP57OOWI4RFHBBKUWMYWRWU6B74O7VODDPYLA")
}

func TestYAMLTemplatePatchedBytecodeMatchesCounterSourceCompile(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}
	tmpl := NewYAMLTemplate(&TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL: `#pragma version 10
int 1
return`,
	})
	teal, err := tmpl.GenerateTEAL(nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	compiled := compileTEALForSaltTest(t, client, teal)
	offset, err := lsigsalt.PushbytesMarkerLocator(compiled)
	if err != nil {
		t.Fatalf("PushbytesMarkerLocator() error = %v", err)
	}
	salted, err := lsigsalt.FindOffCurve(compiled, lsigsalt.PushbytesMarkerLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	counterSource := strings.Replace(teal, "byte 0x"+lsigsalt.PushbytesSaltMarkerHex(0), "byte 0x"+lsigsalt.PushbytesSaltMarkerHex(salted.Counter), 1)
	counterCompiled := compileTEALForSaltTest(t, client, counterSource)

	if !bytes.Equal(counterCompiled, salted.Bytecode) {
		t.Fatalf("compiled counter source does not match patched bytecode")
	}
	assertOnlyOffsetChanged(t, compiled, salted.Bytecode, offset)
}

func TestYAMLTemplateGenerateTEALWithAddressList(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		Parameters: []ParameterSpec{
			{Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 3},
		},
		TEAL: "{{range @recipients}}\naddr {{.}}\n{{end}}\nreturn",
	}

	tmpl := NewYAMLTemplate(spec)

	params := map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ, AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI",
	}

	teal, err := tmpl.GenerateTEAL(params)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	if !strings.Contains(teal, "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ") {
		t.Fatalf("GenerateTEAL() missing first recipient:\n%s", teal)
	}
	if !strings.Contains(teal, "addr AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI") {
		t.Fatalf("GenerateTEAL() missing second recipient:\n%s", teal)
	}
}

func TestLoadTemplatesFromSkipsMalformed(t *testing.T) {
	validYAML := `
publisher: test
family: good
version: 1
display_name: Good Template
teal: "return"
parameters: []
`
	fs := fstest.MapFS{
		"templates/good.yaml":      {Data: []byte(validYAML)},
		"templates/malformed.yaml": {Data: []byte("not: valid: yaml: [")},
		"templates/empty.yaml":     {Data: []byte("")},
		"templates/bad-spec.yaml":  {Data: []byte("family: \"\"\nversion: 0\nteal: return\n")},
		"templates/readme.md":      {Data: []byte("should be ignored")},
	}

	templates, err := loadTemplatesFrom(fs, "templates")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(templates) != 1 {
		t.Errorf("expected 1 valid template, got %d", len(templates))
	}
	if len(templates) > 0 && templates[0].RoutingFamily() != "good" {
		t.Errorf("expected family 'good', got %q", templates[0].RoutingFamily())
	}
}

func TestPrepareKeystoreTemplateRegistrationRejectsStateKeyTypeMismatch(t *testing.T) {
	data := []byte(`
schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: from-yaml
version: 1
display_name: "From YAML"
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
	if _, err := PrepareKeystoreTemplateRegistration("test.from-state.v1", data); err == nil || !strings.Contains(err.Error(), `does not match state key type`) {
		t.Fatalf("PrepareKeystoreTemplateRegistration() error = %v, want state key type mismatch", err)
	}
}

func TestParseTemplateSpecRejectsSaltStyle(t *testing.T) {
	data := []byte(`
schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: salt-style
version: 1
display_name: "Salt Style"
salt_style: pushbytes
teal: |
  int 1
  return
`)
	_, err := ParseTemplateSpec(data)
	if err == nil {
		t.Fatal("ParseTemplateSpec() error = nil, want salt_style rejection")
	}
	if !strings.Contains(err.Error(), "salt_style is not supported") {
		t.Fatalf("ParseTemplateSpec() error = %v, want salt_style rejection", err)
	}
}

func TestTemplateLibraryGenericTemplates(t *testing.T) {
	optInAssets := "10458941,31566704"
	for _, name := range []string{
		"aplane.timed-whitelist.v1.yaml",
		"aplane.whitelist.v1.yaml",
		"aplane.htlc.v1.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", name))
			if err != nil {
				t.Fatalf("failed to read template library file: %v", err)
			}

			spec, err := ParseTemplateSpec(data)
			if err != nil {
				t.Fatalf("template library file has invalid YAML: %v", err)
			}
			if err := ValidateSpec(spec); err != nil {
				t.Fatalf("template library file fails validation: %v", err)
			}
			tmpl := NewYAMLTemplate(spec)
			switch name {
			case "aplane.timed-whitelist.v1.yaml":
				addrA := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
				addrB := "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI"
				params := map[string]string{
					"recipients":   addrA + "," + addrB,
					"unlock_round": "12345",
				}
				teal, err := tmpl.GenerateTEAL(params)
				if err != nil {
					t.Fatalf("GenerateTEAL() error = %v", err)
				}
				if !strings.Contains(teal, "txn Fee\nint 1000\n==\nassert") {
					t.Fatalf("timed whitelist TEAL missing strict fee cap:\n%s", teal)
				}
				normalizedTEAL := strings.Join(strings.Fields(teal), " ")
				for _, addr := range []string{addrA, addrB} {
					if !strings.Contains(normalizedTEAL, "txn Receiver addr "+addr+" ==") {
						t.Fatalf("timed whitelist TEAL missing payment recipient %s:\n%s", addr, teal)
					}
					if !strings.Contains(normalizedTEAL, "txn AssetCloseTo addr "+addr+" ==") {
						t.Fatalf("timed whitelist TEAL missing asset close recipient %s:\n%s", addr, teal)
					}
				}
				assertCompileWithSaltOffCurve(t, tmpl, params)
				if strings.Contains(teal, "txn XferAsset\nint 10458941\n==") {
					t.Fatalf("timed whitelist TEAL unexpectedly contains approved opt-in checks without parameter:\n%s", teal)
				}
				tealWithOptIn, err := tmpl.GenerateTEAL(map[string]string{
					"recipients":           addrA,
					"unlock_round":         "12345",
					"allowed_optin_assets": optInAssets,
				})
				if err != nil {
					t.Fatalf("GenerateTEAL() with allowed_optin_assets error = %v", err)
				}
				for _, assetID := range []string{"10458941", "31566704"} {
					snippet := "txn XferAsset\nint " + assetID + "\n=="
					if !strings.Contains(tealWithOptIn, snippet) {
						t.Fatalf("timed whitelist TEAL missing approved opt-in asset %s:\n%s", assetID, tealWithOptIn)
					}
				}
				if !strings.Contains(tealWithOptIn, "maybe_optin:\ntxn AssetSender\nglobal ZeroAddress\n==\nassert") ||
					!strings.Contains(tealWithOptIn, "bz continue_checks") ||
					!strings.Contains(tealWithOptIn, "txn AssetCloseTo\nglobal ZeroAddress\n==\nassert") {
					t.Fatalf("timed whitelist approved opt-in path must enforce zero close-out:\n%s", tealWithOptIn)
				}
			case "aplane.whitelist.v1.yaml":
				params := map[string]string{
					"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
				}
				teal, err := tmpl.GenerateTEAL(params)
				if err != nil {
					t.Fatalf("GenerateTEAL() error = %v", err)
				}
				if !strings.Contains(teal, "txn Fee\nint 1000\n==\nassert") {
					t.Fatalf("whitelist TEAL missing strict fee cap:\n%s", teal)
				}
				if strings.Contains(teal, "int keyreg\n==\nbnz allow") {
					t.Fatalf("whitelist TEAL still allows keyreg:\n%s", teal)
				}
				assertCompileWithSaltOffCurve(t, tmpl, params)
				if strings.Contains(teal, "txn XferAsset\nint 10458941\n==") {
					t.Fatalf("whitelist TEAL unexpectedly contains approved opt-in asset checks without parameter:\n%s", teal)
				}
				tealWithOptIn, err := tmpl.GenerateTEAL(map[string]string{
					"recipients":           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
					"allowed_optin_assets": optInAssets,
				})
				if err != nil {
					t.Fatalf("GenerateTEAL() with allowed_optin_assets error = %v", err)
				}
				for _, assetID := range []string{"10458941", "31566704"} {
					snippet := "txn XferAsset\nint " + assetID + "\n=="
					if !strings.Contains(tealWithOptIn, snippet) {
						t.Fatalf("whitelist TEAL missing approved opt-in asset %s:\n%s", assetID, tealWithOptIn)
					}
				}
				if !strings.Contains(tealWithOptIn, "maybe_optin:\ntxn AssetCloseTo\nglobal ZeroAddress\n==\nassert") {
					t.Fatalf("whitelist approved opt-in path must enforce zero close-out:\n%s", tealWithOptIn)
				}
			case "aplane.htlc.v1.yaml":
				params := map[string]string{
					"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
					"refund_address": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
					"timeout_round":  "12345",
				}
				teal, err := tmpl.GenerateTEAL(params)
				if err != nil {
					t.Fatalf("GenerateTEAL() error = %v", err)
				}
				if !strings.Contains(teal, "txn Fee\nint 1000\n==\nassert") {
					t.Fatalf("htlc TEAL missing strict fee cap:\n%s", teal)
				}
				if strings.Contains(teal, "txn XferAsset\nint 10458941\n==") {
					t.Fatalf("htlc TEAL unexpectedly contains approved opt-in checks without parameter:\n%s", teal)
				}
				assertCompileWithSaltOffCurve(t, tmpl, params)
				tealWithOptIn, err := tmpl.GenerateTEAL(map[string]string{
					"hash":                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"recipient":            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
					"refund_address":       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
					"timeout_round":        "12345",
					"allowed_optin_assets": optInAssets,
				})
				if err != nil {
					t.Fatalf("GenerateTEAL() with allowed_optin_assets error = %v", err)
				}
				for _, assetID := range []string{"10458941", "31566704"} {
					snippet := "txn XferAsset\nint " + assetID + "\n=="
					if !strings.Contains(tealWithOptIn, snippet) {
						t.Fatalf("htlc TEAL missing approved opt-in asset %s:\n%s", assetID, tealWithOptIn)
					}
				}
				if !strings.Contains(tealWithOptIn, "maybe_optin:\ntxn AssetSender\nglobal ZeroAddress\n==\nassert") ||
					!strings.Contains(tealWithOptIn, "bz continue_paths") ||
					!strings.Contains(tealWithOptIn, "txn AssetCloseTo\nglobal ZeroAddress\n==\nassert") {
					t.Fatalf("htlc approved opt-in path must enforce zero close-out:\n%s", tealWithOptIn)
				}
			}
		})
	}
}

func assertCompileWithSaltOffCurve(t *testing.T, tmpl *YAMLTemplate, params map[string]string) {
	t.Helper()

	var compiled []byte
	if tmpl.spec.DerivationVersion == nil {
		compiled = unsaltedOffCurveBytecodeForTest(t)
	} else {
		switch *tmpl.spec.DerivationVersion {
		case templatestore.DerivationVersionPushbytes:
			compiled = compiledPushbytesSaltBytecode(0)
		case templatestore.DerivationVersionTrailingBytecblock:
			compiled = compiledTrailingBytecblockSaltBytecode(0)
		default:
			t.Fatalf("unsupported derivation version %d", *tmpl.spec.DerivationVersion)
		}
	}
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	result, err := tmpl.CompileWithSalt(context.Background(), params, client)
	if err != nil {
		t.Fatalf("CompileWithSalt() error = %v", err)
	}
	if lsigsalt.IsOnCurve(result.Address) {
		t.Fatalf("CompileWithSalt() returned on-curve address %s", result.Address.String())
	}
}

func unsaltedOffCurveBytecodeForTest(t *testing.T) []byte {
	t.Helper()
	bytecode := []byte{0x0a, 0x81, 0x00}
	for counter := 0; counter < lsigsalt.MaxIterations; counter++ {
		bytecode[2] = byte(counter)
		if _, err := lsigsalt.UseUnmodifiedOffCurve(bytecode); err == nil {
			return append([]byte(nil), bytecode...)
		}
	}
	t.Fatal("failed to find deterministic off-curve unsalted bytecode")
	return nil
}

func compiledPushbytesSaltBytecode(counter byte) []byte {
	marker := lsigsalt.PushbytesSaltMarker(counter)
	bytecode := []byte{0x0a, 0x80, byte(len(marker))}
	bytecode = append(bytecode, marker...)
	bytecode = append(bytecode, 0x48, 0x81, 0x01)
	return bytecode
}

func compiledTrailingBytecblockSaltBytecode(counter byte) []byte {
	return []byte{0x0a, 0x81, 0x01, 0x43, 0x26, 0x01, 0x01, counter}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func compileTEALForSaltTest(t *testing.T, client *algod.Client, teal string) []byte {
	t.Helper()

	result, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return bytecode
}

func assertOnlyOffsetChanged(t *testing.T, before, after []byte, offset int) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("patched bytecode length = %d, want %d", len(after), len(before))
	}
	for i := range before {
		if i == offset {
			continue
		}
		if before[i] != after[i] {
			t.Fatalf("byte offset %d changed: got %x want %x", i, after[i], before[i])
		}
	}
}

func assertGolden(t *testing.T, label, got, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("%s golden: %s", label, got)
	}
	if got != want {
		t.Fatalf("%s = %s, want %s", label, got, want)
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

func TestValidateSpecRejectsNonRelocatableTEAL(t *testing.T) {
	tests := []struct {
		name string
		teal string
	}{
		{
			name: "bytecblock",
			teal: "bytecblock 0xabcd\nbytec 0\nreturn",
		},
		{
			name: "intcblock",
			teal: "intcblock 1 2\nintc 0\nreturn",
		},
		{
			name: "bytec numeric reference",
			teal: "bytec 0\nreturn",
		},
		{
			name: "intc numeric reference",
			teal: "intc 0\nreturn",
		},
		{
			name: "bytec shorthand",
			teal: "bytec_0\nreturn",
		},
		{
			name: "intc shorthand",
			teal: "intc_1\nreturn",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := &TemplateSpec{
				BaseTemplateSpec: testBase(),
				TEAL:             tc.teal,
			}
			err := ValidateSpec(spec)
			if err == nil {
				t.Fatal("ValidateSpec() error = nil, want relocatable TEAL error")
			}
			if !strings.Contains(err.Error(), "template TEAL must be relocatable") {
				t.Fatalf("ValidateSpec() error = %v, want relocatable TEAL error", err)
			}
		})
	}
}

func TestValidateSpecRelocatableTEALAllowsCommentsAndSymbolicVariables(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		Parameters: []ParameterSpec{
			{Name: "hash", Type: "bytes", Required: true, MaxLength: 32},
		},
		TEAL: `// bytecblock 0xabcd is ignored in comments
arg 0 // bytec 0 in an inline comment is ignored
sha256
byte @hash
==
return`,
	}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() error = %v, want nil", err)
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
				Required:    true,
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
	if !arg.Required {
		t.Error("expected Required true, got false")
	}
	if arg.ByteLength != 32 {
		t.Errorf("expected ByteLength 32, got %d", arg.ByteLength)
	}
}

func TestBuildArgsValidation(t *testing.T) {
	spec := &TemplateSpec{
		BaseTemplateSpec: testBase(),
		TEAL:             "return",
		RuntimeArgs: []RuntimeArgSpec{
			{Name: "preimage", Type: "bytes", Required: true, ByteLength: 4},
			{Name: "optional", Type: "bytes"},
		},
	}
	tmpl := NewYAMLTemplate(spec)

	t.Run("valid args", func(t *testing.T) {
		args, err := tmpl.BuildArgs(nil, map[string][]byte{
			"preimage": {0xde, 0xad, 0xbe, 0xef},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(args) != 1 {
			t.Errorf("expected 1 arg, got %d", len(args))
		}
	})

	t.Run("missing required arg", func(t *testing.T) {
		_, err := tmpl.BuildArgs(nil, map[string][]byte{})
		if err == nil || !strings.Contains(err.Error(), "missing required arg") {
			t.Errorf("expected missing required arg error, got: %v", err)
		}
	})

	t.Run("wrong byte length", func(t *testing.T) {
		_, err := tmpl.BuildArgs(nil, map[string][]byte{
			"preimage": {0xde, 0xad}, // 2 bytes, expected 4
		})
		if err == nil || !strings.Contains(err.Error(), "expected 4 bytes, got 2") {
			t.Errorf("expected byte length error, got: %v", err)
		}
	})

	t.Run("unknown arg rejected", func(t *testing.T) {
		_, err := tmpl.BuildArgs(nil, map[string][]byte{
			"preimage": {0xde, 0xad, 0xbe, 0xef},
			"typo":     {0x01},
		})
		if err == nil || !strings.Contains(err.Error(), "unknown arg") {
			t.Errorf("expected unknown arg error, got: %v", err)
		}
	})
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

func TestValidateDefaultValueMatchesRuntimeByteLength(t *testing.T) {
	// A bytes param with unset MaxLength gets a 64-hex-char (32-byte) default
	// at runtime; spec-time default validation must enforce the same length
	// instead of silently accepting a default that fails at use time.
	short := ParameterSpec{Name: "k", Type: "bytes", Default: "00"}
	if err := validateDefaultValue(short); err == nil {
		t.Fatal("1-byte default with unset MaxLength must fail spec validation (runtime enforces 32 bytes)")
	}

	ok := ParameterSpec{Name: "k", Type: "bytes", Default: strings.Repeat("ab", 32)}
	if err := validateDefaultValue(ok); err != nil {
		t.Fatalf("32-byte default should pass: %v", err)
	}

	explicit := ParameterSpec{Name: "k", Type: "bytes", MaxLength: 8, Default: "00112233"}
	if err := validateDefaultValue(explicit); err != nil {
		t.Fatalf("explicit MaxLength default should pass: %v", err)
	}
}
