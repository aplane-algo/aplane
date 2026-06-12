// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	algoutil "github.com/aplane-algo/aplane/internal/algo"
	"github.com/dop251/goja"
)

// maxSafeUint64Float is the exclusive upper bound for a float64 -> uint64
// conversion. At or above 2^63 the cast is implementation-defined (it produces
// garbage), so such values are rejected. Note that float64 cannot represent
// consecutive integers above 2^53; an amount that large was already rounded by
// the JS engine before it reached Go, so the precise bound only needs to fence
// off the garbage-cast region.
const maxSafeUint64Float = float64(1 << 63)

// validateUint64Float rejects float64 amounts that cannot be converted to a
// uint64 base-unit count without silent loss: NaN/Inf, negative, non-integral
// (e.g. 1.5, which a bare cast would truncate to 1), and values in the
// garbage-cast region. JS numbers are float64, so callers building transaction
// amounts/fees from JS must run this before casting.
func validateUint64Float(val float64) error {
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return fmt.Errorf("value must be a finite number")
	}
	if val < 0 {
		return errNegativeValue
	}
	if val != math.Trunc(val) {
		return fmt.Errorf("value must be a whole number of base units (got %v)", val)
	}
	if val >= maxSafeUint64Float {
		return fmt.Errorf("value %v is too large", val)
	}
	return nil
}

// makeAlgoFunc creates the algo() helper function bound to a runtime.
// algo(1.5) -> 1500000
func makeAlgoFunc(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("algo() requires a number argument"))
		}

		val := call.Arguments[0].ToFloat()
		if math.IsNaN(val) || math.IsInf(val, 0) {
			panic(vm.ToValue("algo() requires a finite number"))
		}
		if val < 0 {
			panic(vm.ToValue("algo() cannot be negative"))
		}
		// Convert through exact decimal-string arithmetic rather than float
		// multiply + round, so fractional ALGO never silently loses
		// sub-microAlgo precision (algo(0.0000001) is rejected, not rounded to
		// 0) and the result matches the CLI's string-based conversion.
		// FormatFloat(-1) yields the shortest round-tripping decimal, so 0.1
		// becomes "0.1", not its float64 expansion.
		microAlgos, err := algoutil.ConvertTokenAmountToBaseUnits(strconv.FormatFloat(val, 'f', -1, 64), 6)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("algo() invalid amount: %v", err)))
		}
		return vm.ToValue(microAlgos)
	}
}

// makeMicroalgosFunc creates the microalgos() helper function bound to a runtime.
// microalgos(1500000) -> 1500000
func makeMicroalgosFunc(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("microalgos() requires a number argument"))
		}

		val := toUint64(vm, call.Arguments[0])
		return vm.ToValue(val)
	}
}

// requireArgs panics with a JS exception if the call has fewer than n arguments.
func (a *API) requireArgs(call goja.FunctionCall, n int, msg string) {
	if len(call.Arguments) < n {
		panic(a.runtime.ToValue(msg))
	}
}

func (a *API) objectArg(call goja.FunctionCall, argIndex int, funcName string) map[string]interface{} {
	if len(call.Arguments) <= argIndex || goja.IsUndefined(call.Arguments[argIndex]) || goja.IsNull(call.Arguments[argIndex]) {
		return nil
	}
	m, ok := call.Arguments[argIndex].Export().(map[string]interface{})
	if !ok {
		panic(a.runtime.ToValue(fmt.Sprintf("%s options must be an object", funcName)))
	}
	return m
}

// toJSObject converts a Go value into a JSON-compatible JavaScript object.
func (a *API) toJSObject(v interface{}) goja.Value {
	encoded, err := json.Marshal(v)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("failed to marshal JS object: %v", err)))
	}

	var decoded interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("failed to unmarshal JS object: %v", err)))
	}

	return a.runtime.ToValue(decoded)
}

// toUint64 converts a Goja value to uint64.
// Panics with a JS exception if the value is negative.
func toUint64(vm *goja.Runtime, v goja.Value) uint64 {
	switch val := v.Export().(type) {
	case int64:
		if val < 0 {
			panic(vm.ToValue("value cannot be negative"))
		}
		return uint64(val)
	case float64:
		if err := validateUint64Float(val); err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return uint64(val)
	case int:
		if val < 0 {
			panic(vm.ToValue("value cannot be negative"))
		}
		return uint64(val)
	case uint64:
		return val
	default:
		i := v.ToInteger()
		if i < 0 {
			panic(vm.ToValue("value cannot be negative"))
		}
		return uint64(i)
	}
}

// errNegativeValue is returned when a negative value is passed where uint64 is expected.
var errNegativeValue = fmt.Errorf("value cannot be negative")

// toUint64Interface converts an interface{} to uint64.
// Returns error for negative values or unsupported types.
func toUint64Interface(v interface{}) (uint64, error) {
	switch val := v.(type) {
	case int64:
		if val < 0 {
			return 0, errNegativeValue
		}
		return uint64(val), nil
	case float64:
		if err := validateUint64Float(val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case int:
		if val < 0 {
			return 0, errNegativeValue
		}
		return uint64(val), nil
	case uint64:
		return val, nil
	default:
		return 0, fmt.Errorf("unsupported type for uint64 conversion: %T", v)
	}
}

// txnOptions holds common transaction options parsed from JS call arguments.
type txnOptions struct {
	Fee        uint64
	UseFlatFee bool
	Wait       bool
	Note       string
}

type closeTxnOptions struct {
	txnOptions
	LsigArgs map[string][]byte
}

// parseTxnOptions extracts {fee, wait, note} from an optional options argument.
// argIndex is the position of the options argument in the call.
// funcName is used for error messages.
func (a *API) parseTxnOptions(call goja.FunctionCall, argIndex int, funcName string) txnOptions {
	opts := txnOptions{Wait: true}
	m := a.objectArg(call, argIndex, funcName)
	if m == nil {
		return opts
	}
	if f, ok := m["fee"]; ok {
		var err error
		opts.Fee, err = toUint64Interface(f)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid fee: %v", funcName, err)))
		}
		opts.UseFlatFee = true
	}
	if w, ok := m["wait"].(bool); ok {
		opts.Wait = w
	}
	if n, ok := m["note"].(string); ok {
		opts.Note = n
	}
	return opts
}

// parseOptOutArgs handles optOut's overloaded argument parsing.
// Supports: (acct, id), (acct, id, closeTo), (acct, id, opts),
// (acct, id, closeTo, opts), and (acct, id, null, opts).
func (a *API) parseOptOutArgs(call goja.FunctionCall) (string, txnOptions) {
	opts := txnOptions{Wait: true}
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		arg2 := call.Arguments[2].Export()
		if s, ok := arg2.(string); ok {
			return s, a.parseTxnOptions(call, 3, "optOut()")
		}
		if _, ok := arg2.(map[string]interface{}); ok {
			return "", a.parseTxnOptions(call, 2, "optOut()")
		}
		return "", opts
	}
	// arg2 absent, null, or undefined — check arg3 for options
	return "", a.parseTxnOptions(call, 3, "optOut()")
}

func (a *API) parseCloseOptions(call goja.FunctionCall) closeTxnOptions {
	opts := closeTxnOptions{txnOptions: a.parseTxnOptions(call, 2, "close()")}
	m := a.objectArg(call, 2, "close()")
	if m == nil {
		return opts
	}

	rawArgs, ok := m["lsigArgs"]
	if !ok {
		return opts
	}

	argMap, ok := rawArgs.(map[string]interface{})
	if !ok {
		panic(a.runtime.ToValue("close() invalid lsigArgs: expected object"))
	}

	opts.LsigArgs = make(map[string][]byte, len(argMap))
	for name, raw := range argMap {
		value, err := parseJSByteString(raw)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("close() invalid lsigArgs[%q]: %v", name, err)))
		}
		opts.LsigArgs[name] = value
	}

	return opts
}

// toStringArray converts a Goja value to []string.
func toStringArray(v goja.Value) []string {
	return toStringArrayValue(v.Export())
}

func toStringArrayValue(v interface{}) []string {
	switch arr := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return arr
	default:
		return nil
	}
}

func toInterfaceArray(v goja.Value) []interface{} {
	return toInterfaceSliceValue(v.Export())
}

func toInterfaceSliceValue(v interface{}) []interface{} {
	switch arr := v.(type) {
	case []interface{}:
		return arr
	case []string:
		result := make([]interface{}, len(arr))
		for i, item := range arr {
			result[i] = item
		}
		return result
	default:
		return nil
	}
}
