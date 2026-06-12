// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
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

		// Application functions (apps.go)
		{
			name:      "appGlobal no args",
			jsCode:    "appGlobal()",
			wantError: "appGlobal() requires an appId argument",
		},
		{
			name:      "appLocal no args",
			jsCode:    "appLocal()",
			wantError: "appLocal() requires appId and account arguments",
		},
		{
			name:      "appBox no args",
			jsCode:    "appBox()",
			wantError: "appBox() requires appId and box name arguments",
		},
		{
			name:      "appBoxes no args",
			jsCode:    "appBoxes()",
			wantError: "appBoxes() requires an appId argument",
		},
		{
			name:      "appCallRaw no args",
			jsCode:    "appCallRaw()",
			wantError: "appCallRaw() requires appId, from, and appArgs arguments",
		},
		{
			name:      "appCall no args",
			jsCode:    "appCall()",
			wantError: "appCall() requires appId, method, abiPath, from, and args arguments",
		},
		{
			name:      "appDeploy no args",
			jsCode:    "appDeploy()",
			wantError: "appDeploy() requires from, approvalPath, and clearPath arguments",
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

func TestAppCallRawAllowsZeroArgs(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	addr := types.Address{}.String()
	tests := []struct {
		name   string
		jsCode string
	}{
		{
			name:   "zero args",
			jsCode: fmt.Sprintf(`appCallRaw(123, %q, [])`, addr),
		},
		{
			name:   "one arg",
			jsCode: fmt.Sprintf(`appCallRaw(123, %q, ["text:arg"])`, addr),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vm.RunString(tt.jsCode)
			if err == nil {
				t.Fatal("expected error but got none")
			}
			if strings.Contains(err.Error(), "requires at least one app arg") {
				t.Fatalf("unexpected arg-count validation error: %v", err)
			}
			if !strings.Contains(err.Error(), engine.ErrNoAlgodClient.Error()) {
				t.Fatalf("expected ErrNoAlgodClient, got %v", err)
			}
		})
	}
}

func TestAppCallRawRejectsNonArrayArgs(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	addr := types.Address{}.String()
	_, err = vm.RunString(fmt.Sprintf(`appCallRaw(123, %q, "not-array")`, addr))
	if err == nil || !strings.Contains(err.Error(), "appCallRaw() appArgs must be an array") {
		t.Fatalf("expected non-array appArgs error, got %v", err)
	}
}

func TestAppCallValidationRejectsEmptyABIPathAndEmptyBoxName(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("failed to register API: %v", err)
	}

	addr := types.Address{}.String()

	_, err = vm.RunString(fmt.Sprintf(`appCall(123, "increment", "", %q, ["5"])`, addr))
	if err == nil || !strings.Contains(err.Error(), "ABI path is required") {
		t.Fatalf("expected empty ABI path error, got %v", err)
	}

	_, err = vm.RunString(fmt.Sprintf(`appCallRaw(123, %q, [], {boxes:[""]})`, addr))
	if err == nil || !strings.Contains(err.Error(), "box name must be non-empty") {
		t.Fatalf("expected empty box name error, got %v", err)
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

// TestAmountConversionsRejectImprecise pins the unit-conversion hardening:
// fractional microAlgos and non-integral / out-of-range base-unit amounts must
// error rather than silently truncate or round to a wrong value.
func TestAmountConversionsRejectImprecise(t *testing.T) {
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
		{"algo sub-microalgo precision", "algo(0.0000001)", "decimal places"},
		{"microalgos fractional truncates", "microalgos(1.5)", "whole number"},
		{"microalgos out of range", "microalgos(1e36)", "too large"},
		{"microalgos NaN", "microalgos(0/0)", "finite"},
		// A string amount reaches toUint64's default case; it must run the same
		// whole-number validation as a numeric float rather than truncating via
		// ToInteger() ("1.5" -> 1).
		{"microalgos fractional string truncates", "microalgos(\"1.5\")", "whole number"},
		{"microalgos non-numeric string", "microalgos(\"abc\")", "finite"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vm.RunString(tt.jsCode)
			if err == nil {
				t.Fatalf("%s: expected error, got none", tt.jsCode)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("%s: error = %q, want containing %q", tt.jsCode, err.Error(), tt.wantError)
			}
		})
	}
}

// TestGetAsaId tests well-known asset lookup.
func TestGetAsaId(t *testing.T) {
	eng, err := engine.NewEngine("mainnet")
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
		want   interface{} // int64 for found, nil for null
	}{
		{"mainnet usdc", `getAsaId("usdc")`, int64(31566704)},
		{"mainnet USDC case insensitive", `getAsaId("USDC")`, int64(31566704)},
		{"mainnet builtin not in old JS table", `getAsaId("gousd")`, int64(672913181)},
		{"mainnet explicit alias", `getAsaId("akita")`, int64(523683256)},
		{"mainnet usdt returns null", `getAsaId("usdt")`, nil},
		{"testnet usdc via network arg", `getAsaId("usdc", "testnet")`, int64(10458941)},
		{"unknown asset returns null", `getAsaId("nonexistent")`, nil},
		{"unknown network returns null", `getAsaId("usdc", "devnet")`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vm.RunString(tt.jsCode)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tt.jsCode, err)
			}

			if tt.want == nil {
				if !goja.IsNull(result) {
					t.Errorf("%s = %v, want null", tt.jsCode, result.Export())
				}
				return
			}

			got := result.ToInteger()
			if got != tt.want.(int64) {
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
