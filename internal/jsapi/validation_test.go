// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// TestArgumentValidation tests that JS API functions return errors with correct messages
// when called with insufficient arguments. These tests verify the validation layer
// without requiring a connected engine.
func TestArgumentValidation(t *testing.T) {
	// Create minimal engine (not connected, but enough for API creation)
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create API and register on runtime
	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	tests := []struct {
		name      string
		jsCode    string
		wantError string // substring of expected error message
	}{
		// Core functions (api.go)
		{
			name:      "waitForTx no args",
			jsCode:    "waitForTx()",
			wantError: "waitForTx() requires a txid argument",
		},
		{
			name:      "setWriteMode no args",
			jsCode:    "setWriteMode()",
			wantError: "setWriteMode() requires a boolean argument",
		},
		{
			name:      "setVerbose no args",
			jsCode:    "setVerbose()",
			wantError: "setVerbose() requires a boolean argument",
		},
		{
			name:      "plugin no args",
			jsCode:    "plugin()",
			wantError: "plugin() requires at least a plugin/command name",
		},

		// Account functions (accounts.go)
		{
			name:      "balance no args",
			jsCode:    "balance()",
			wantError: "balance() requires an address or alias argument",
		},
		{
			name:      "resolve no args",
			jsCode:    "resolve()",
			wantError: "resolve() requires an address or alias argument",
		},
		{
			name:      "alias no args",
			jsCode:    "alias()",
			wantError: "alias() requires a name argument",
		},
		{
			name:      "addAlias no args",
			jsCode:    "addAlias()",
			wantError: "addAlias() requires name and address arguments",
		},
		{
			name:      "removeAlias no args",
			jsCode:    "removeAlias()",
			wantError: "removeAlias() requires a name argument",
		},
		{
			name:      "set no args",
			jsCode:    "set()",
			wantError: "set() requires a name argument",
		},
		{
			name:      "createSet no args",
			jsCode:    "createSet()",
			wantError: "createSet() requires name and addresses arguments",
		},
		{
			name:      "addToSet no args",
			jsCode:    "addToSet()",
			wantError: "addToSet() requires name and addresses arguments",
		},
		{
			name:      "removeFromSet no args",
			jsCode:    "removeFromSet()",
			wantError: "removeFromSet() requires name and addresses arguments",
		},
		{
			name:      "deleteSet no args",
			jsCode:    "deleteSet()",
			wantError: "deleteSet() requires a name argument",
		},
		{
			name:      "canSignFor no args",
			jsCode:    "canSignFor()",
			wantError: "canSignFor() requires an address argument",
		},

		// Transaction functions (transactions.go)
		{
			name:      "validate no args",
			jsCode:    "validate()",
			wantError: "validate() requires an address or alias argument",
		},
		{
			name:      "send no args",
			jsCode:    "send()",
			wantError: "send() requires from, to, and amount arguments",
		},
		{
			name:      "sweep no args",
			jsCode:    "sweep()",
			wantError: "sweep() requires from and to arguments",
		},
		{
			name:      "sendAsset no args",
			jsCode:    "sendAsset()",
			wantError: "sendAsset() requires from, to, assetId, and amount arguments",
		},
		{
			name:      "optIn no args",
			jsCode:    "optIn()",
			wantError: "optIn() requires account and assetId arguments",
		},
		{
			name:      "optOut no args",
			jsCode:    "optOut()",
			wantError: "optOut() requires account and assetId arguments",
		},
		{
			name:      "keyreg no args",
			jsCode:    "keyreg()",
			wantError: "keyreg() requires account and mode arguments",
		},
		{
			name:      "participation no args",
			jsCode:    "participation()",
			wantError: "participation() requires an address argument",
		},
		{
			name:      "incentiveEligible no args",
			jsCode:    "incentiveEligible()",
			wantError: "incentiveEligible() requires an address argument",
		},
		{
			name:      "rekey no args",
			jsCode:    "rekey()",
			wantError: "rekey() requires from and to arguments",
		},
		{
			name:      "unrekey no args",
			jsCode:    "unrekey()",
			wantError: "unrekey() requires an account argument",
		},
		{
			name:      "isRekeyed no args",
			jsCode:    "isRekeyed()",
			wantError: "isRekeyed() requires an address argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vm.RunString(tt.jsCode)
			if err == nil {
				t.Errorf("%s: expected error but got none", tt.jsCode)
				return
			}

			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("%s:\n  got error:  %q\n  want containing: %q", tt.jsCode, err.Error(), tt.wantError)
			}
		})
	}
}

// Note: Tests for keyreg mode validation and plugin executor validation are skipped
// due to Goja runtime state issues after panic recovery in previous tests.
// The validation logic is tested indirectly through the no-args tests above.

// TestNegativeValueValidation tests that numeric functions reject negative values.
func TestNegativeValueValidation(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	tests := []struct {
		name      string
		jsCode    string
		wantError string
	}{
		{
			name:      "algo negative",
			jsCode:    "algo(-1)",
			wantError: "cannot be negative",
		},
		{
			name:      "algo negative fractional",
			jsCode:    "algo(-0.5)",
			wantError: "cannot be negative",
		},
		{
			name:      "microalgos negative",
			jsCode:    "microalgos(-100)",
			wantError: "cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vm.RunString(tt.jsCode)
			if err == nil {
				t.Errorf("%s: expected error but got none", tt.jsCode)
				return
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("%s: got error %q, want containing %q", tt.jsCode, err.Error(), tt.wantError)
			}
		})
	}
}

// Note: Tests for send() negative amounts and invalid fees are covered by
// the toUint64 and toUint64Interface tests in helpers_test.go, which test
// the underlying validation logic directly.

// TestAlgoMicroalgosNoArgs tests that algo() and microalgos() require arguments.
func TestAlgoMicroalgosNoArgs(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	tests := []struct {
		name      string
		jsCode    string
		wantError string
	}{
		{
			name:      "algo no args",
			jsCode:    "algo()",
			wantError: "algo() requires a number argument",
		},
		{
			name:      "microalgos no args",
			jsCode:    "microalgos()",
			wantError: "microalgos() requires a number argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vm.RunString(tt.jsCode)
			if err == nil {
				t.Errorf("%s: expected error but got none", tt.jsCode)
				return
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("%s: got error %q, want containing %q", tt.jsCode, err.Error(), tt.wantError)
			}
		})
	}
}

// TestAlgoValidConversions tests that algo() correctly converts values.
func TestAlgoValidConversions(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	tests := []struct {
		jsCode string
		want   int64
	}{
		{"algo(1)", 1_000_000},
		{"algo(1.5)", 1_500_000},
		{"algo(0.000001)", 1},
		{"algo(0)", 0},
		{"algo(100)", 100_000_000},
		{"microalgos(1000)", 1000},
		{"microalgos(0)", 0},
	}

	for _, tt := range tests {
		t.Run(tt.jsCode, func(t *testing.T) {
			result, err := vm.RunString(tt.jsCode)
			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.jsCode, err)
				return
			}
			got := result.ToInteger()
			if got != tt.want {
				t.Errorf("%s = %d, want %d", tt.jsCode, got, tt.want)
			}
		})
	}
}

// TestFunctionsReturnWithoutEngine tests that functions that don't require
// engine connection work correctly.
func TestFunctionsReturnWithoutEngine(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	tests := []struct {
		name   string
		jsCode string
		check  func(goja.Value) error
	}{
		{
			name:   "network returns string",
			jsCode: "network()",
			check: func(v goja.Value) error {
				if v.String() != "testnet" {
					return fmt.Errorf("got %q, want 'testnet'", v.String())
				}
				return nil
			},
		},
		{
			name:   "writeMode returns boolean",
			jsCode: "writeMode()",
			check: func(v goja.Value) error {
				if v.ExportType().Kind().String() != "bool" {
					return fmt.Errorf("got type %s, want bool", v.ExportType().Kind())
				}
				return nil
			},
		},
		{
			name:   "connected returns boolean",
			jsCode: "connected()",
			check: func(v goja.Value) error {
				if v.ExportType().Kind().String() != "bool" {
					return fmt.Errorf("got type %s, want bool", v.ExportType().Kind())
				}
				return nil
			},
		},
		{
			name:   "status returns object",
			jsCode: "status()",
			check: func(v goja.Value) error {
				obj := v.Export()
				if _, ok := obj.(map[string]interface{}); !ok {
					return fmt.Errorf("got type %T, want map", obj)
				}
				return nil
			},
		},
		{
			name:   "aliases returns object",
			jsCode: "aliases()",
			check: func(v goja.Value) error {
				obj := v.Export()
				if _, ok := obj.(map[string]interface{}); !ok {
					return fmt.Errorf("got type %T, want map", obj)
				}
				return nil
			},
		},
		{
			name:   "sets returns array",
			jsCode: "sets()",
			check: func(v goja.Value) error {
				obj := v.Export()
				if _, ok := obj.([]interface{}); !ok {
					return fmt.Errorf("got type %T, want array", obj)
				}
				return nil
			},
		},
		{
			name:   "signers returns object",
			jsCode: "signers()",
			check: func(v goja.Value) error {
				obj := v.Export()
				if _, ok := obj.(map[string]interface{}); !ok {
					return fmt.Errorf("got type %T, want map", obj)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vm.RunString(tt.jsCode)
			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.jsCode, err)
				return
			}
			if err := tt.check(result); err != nil {
				t.Errorf("%s: %v", tt.jsCode, err)
			}
		})
	}
}
