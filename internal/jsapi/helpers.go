// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsapi

import (
	"fmt"
	"math"

	"github.com/dop251/goja"
)

// makeAlgoFunc creates the algo() helper function bound to a runtime.
// algo(1.5) -> 1500000
func makeAlgoFunc(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("algo() requires a number argument"))
		}

		val := call.Arguments[0].ToFloat()
		if val < 0 {
			panic(vm.ToValue("algo() cannot be negative"))
		}
		microAlgos := uint64(math.Round(val * 1_000_000))
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
		if val < 0 {
			panic(vm.ToValue("value cannot be negative"))
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
		if val < 0 {
			return 0, errNegativeValue
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

// toStringArray converts a Goja value to []string.
func toStringArray(v goja.Value) []string {
	exported := v.Export()
	switch arr := exported.(type) {
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
