// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"

	algoutil "github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/appresult"
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
	// Past this, JavaScript has already rounded the number.
	if val > maxSafeJSInteger {
		return fmt.Errorf("value %.0f is past the largest whole number JavaScript holds exactly; pass a BigInt or a decimal string", val)
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

		// A number, and nothing coerced to one: algo(null) and algo('') would
		// be 0 ALGO, algo(true) 1 ALGO, algo('1e6') a million.
		var val float64
		switch exported := call.Arguments[0].Export().(type) {
		case int64:
			val = float64(exported)
		case float64:
			val = exported
		default:
			panic(vm.ToValue(fmt.Sprintf("algo() requires a number, got %s", jsTypeName(exported))))
		}
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

// throwSubmitError throws the failure of a function that submits. Every
// submitting function throws its submission failure through here. The
// exception is an Error whose message is err's text, and whose string form,
// uncaught or concatenated, is that text alone, as the string thrown before
// it was. When err carries submission outcomes
// (appresult.SubmissionsFromError), the Error has txids, every ID of the
// failed submissions in order, and, when there is one, submission, its
// state. The outcomes are also recorded for the run when its context has a
// recorder (RecordSubmissions), so the host reports them whether or not the
// script catches the error.
func (a *API) throwSubmitError(err error) {
	submissions := appresult.SubmissionsFromError(err)
	if recorder, ok := a.Context().Value(submissionRecorderKey{}).(*submissionRecorder); ok {
		recorder.add(submissions)
	}
	obj := a.runtime.NewGoError(err)
	// A GoError's name would print "GoError: " before the message.
	_ = obj.DefineDataProperty("name", a.runtime.ToValue(""), goja.FLAG_TRUE, goja.FLAG_TRUE, goja.FLAG_FALSE)
	if len(submissions) > 0 {
		var ids []interface{}
		for _, submission := range submissions {
			for _, id := range submission.TxIDs {
				ids = append(ids, id)
			}
		}
		_ = obj.Set("txids", a.runtime.NewArray(ids...))
		if len(submissions) == 1 {
			_ = obj.Set("submission", submissions[0].State)
		}
	}
	panic(obj)
}

type submissionRecorderKey struct{}

// submissionRecorder holds the outcomes of the submission failures the JS
// functions threw during one run, in order.
type submissionRecorder struct {
	mu          sync.Mutex
	submissions []appresult.Submission
}

func (r *submissionRecorder) add(submissions []appresult.Submission) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.submissions = append(r.submissions, submissions...)
}

func (r *submissionRecorder) recorded() []appresult.Submission {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]appresult.Submission(nil), r.submissions...)
}

// RecordSubmissions returns ctx for one script run, under which every
// submission failure a JS function throws is recorded, whether or not the
// script catches it, and a function that returns the outcomes recorded so
// far, in order.
func RecordSubmissions(ctx context.Context) (context.Context, func() []appresult.Submission) {
	recorder := &submissionRecorder{}
	return context.WithValue(ctx, submissionRecorderKey{}, recorder), recorder.recorded
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
		// A decimal string or a BigInt for a value JavaScript can't hold
		// exactly. Nothing else: null, undefined, booleans and objects
		// would be coerced to 0, 0, 1 and NaN, and "0x10", "1e6" and ""
		// read as numbers the script did not write.
		parsed, err := toUint64Interface(val)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return parsed
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
	case string:
		// A decimal string, as toUint64 takes: the way to pass a value
		// JavaScript can't hold exactly.
		parsed, err := strconv.ParseUint(val, 10, 64)
		if err != nil || (len(val) > 1 && val[0] == '0') {
			return 0, fmt.Errorf("%q is not a whole number in plain decimal", val)
		}
		return parsed, nil
	case *big.Int:
		if val.Sign() < 0 {
			return 0, errNegativeValue
		}
		if !val.IsUint64() {
			return 0, fmt.Errorf("value %s is too large", val.String())
		}
		return val.Uint64(), nil
	default:
		return 0, fmt.Errorf("a number is needed, got %s", jsTypeName(v))
	}
}

// refuseUnknownKeys raises a JS error for a key the caller does not read.
func (a *API) refuseUnknownKeys(m map[string]interface{}, what string, allowed ...string) {
	for key := range m {
		if !slices.Contains(allowed, key) {
			known := append([]string(nil), allowed...)
			slices.Sort(known)
			panic(a.runtime.ToValue(fmt.Sprintf("%s %q is not known (known: %s)", what, key, strings.Join(known, ", "))))
		}
	}
}

// boolArg reads a function argument that must be true or false. JavaScript
// would coerce anything else: undefined to false, and the text 'false' to
// true.
func (a *API) boolArg(call goja.FunctionCall, index int, funcName string) bool {
	value, ok := call.Arguments[index].Export().(bool)
	if !ok {
		panic(a.runtime.ToValue(fmt.Sprintf("%s requires true or false, got %s", funcName, jsTypeName(call.Arguments[index].Export()))))
	}
	return value
}

// optionBool reads a boolean option. An option that is present with another
// type is an error: {wait: 'false'} read as "not given" would wait.
func (a *API) optionBool(m map[string]interface{}, key, funcName string) (value, present bool) {
	raw, exists := m[key]
	if !exists || raw == nil {
		return false, false
	}
	value, ok := raw.(bool)
	if !ok {
		panic(a.runtime.ToValue(fmt.Sprintf("%s option %s must be true or false, got %s", funcName, key, jsTypeName(raw))))
	}
	return value, true
}

// optionUint64 reads a whole-number option: a fee, an amount, an ID. A key
// that is present must hold a number; {leaving: undefined}, from a mistyped
// or unset variable, read as "not given" would move a different amount than
// the script meant.
func (a *API) optionUint64(m map[string]interface{}, key, funcName string) (value uint64, present bool) {
	raw, exists := m[key]
	if !exists {
		return 0, false
	}
	value, err := toUint64Interface(raw)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("%s invalid %s: %v", funcName, key, err)))
	}
	return value, true
}

// lsigArgsOption reads the lsigArgs option: LogicSig runtime arguments by
// name, each a byte string.
func (a *API) lsigArgsOption(m map[string]interface{}, funcName string) map[string][]byte {
	rawArgs, ok := m["lsigArgs"]
	if !ok {
		return nil
	}
	argMap, ok := rawArgs.(map[string]interface{})
	if !ok {
		panic(a.runtime.ToValue(funcName + " invalid lsigArgs: expected object"))
	}
	args := make(map[string][]byte, len(argMap))
	for name, raw := range argMap {
		value, err := parseJSByteString(raw)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid lsigArgs[%q]: %v", funcName, name, err)))
		}
		args[name] = value
	}
	return args
}

// optionString reads a string option, with the same rule as optionBool.
func (a *API) optionString(m map[string]interface{}, key, funcName string) (value string, present bool) {
	raw, exists := m[key]
	if !exists || raw == nil {
		return "", false
	}
	value, ok := raw.(string)
	if !ok {
		panic(a.runtime.ToValue(fmt.Sprintf("%s option %s must be a string, got %s", funcName, key, jsTypeName(raw))))
	}
	return value, true
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
//
// extraKeys names the other options the calling function reads from the same
// object. Any key outside {fee, wait, note} and those is refused: an option
// that is not read is an option that was ignored, such as {Fee: 0} or
// {nowait: true}.
func (a *API) parseTxnOptions(call goja.FunctionCall, argIndex int, funcName string, extraKeys ...string) txnOptions {
	opts := txnOptions{Wait: true}
	m := a.objectArg(call, argIndex, funcName)
	if m == nil {
		return opts
	}
	a.refuseUnknownKeys(m, funcName+" option", append([]string{"fee", "wait", "note"}, extraKeys...)...)
	opts.Fee, opts.UseFlatFee = a.optionUint64(m, "fee", funcName)
	if w, ok := a.optionBool(m, "wait", funcName); ok {
		opts.Wait = w
	}
	if n, ok := a.optionString(m, "note", funcName); ok {
		opts.Note = n
	}
	return opts
}

// parseOptOutArgs handles optOut's overloaded argument parsing.
// Supports: (acct, id), (acct, id, closeTo), (acct, id, opts),
// (acct, id, closeTo, opts), and (acct, id, null, opts).
func (a *API) parseOptOutArgs(call goja.FunctionCall) (string, txnOptions) {
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		arg2 := call.Arguments[2].Export()
		if s, ok := arg2.(string); ok {
			return s, a.parseTxnOptions(call, 3, "optOut()")
		}
		if _, ok := arg2.(map[string]interface{}); ok {
			return "", a.parseTxnOptions(call, 2, "optOut()")
		}
		panic(a.runtime.ToValue(fmt.Sprintf(
			"optOut() third argument must be a close-to address or an options object, got %s", jsTypeName(arg2))))
	}
	// arg2 absent, null, or undefined — check arg3 for options
	return "", a.parseTxnOptions(call, 3, "optOut()")
}

func (a *API) parseCloseOptions(call goja.FunctionCall) closeTxnOptions {
	opts := closeTxnOptions{txnOptions: a.parseTxnOptions(call, 2, "close()", "lsigArgs")}
	m := a.objectArg(call, 2, "close()")
	if m == nil {
		return opts
	}

	opts.LsigArgs = a.lsigArgsOption(m, "close()")
	return opts
}

// stringArray reads a JavaScript array of strings. An entry that is not a
// string is an error: dropping it would shorten the list and move every
// later entry, and a program reads accounts by position.
func stringArray(v interface{}) ([]string, error) {
	switch arr := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(arr))
		for i, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("entry %d is %s, not a string", i+1, jsTypeName(item))
			}
			result = append(result, s)
		}
		return result, nil
	case []string:
		return arr, nil
	default:
		return nil, fmt.Errorf("expected an array of strings, got %s", jsTypeName(v))
	}
}

// stringArrayArg is stringArray for a function argument, raising a JS error.
func (a *API) stringArrayArg(v goja.Value, what string) []string {
	result, err := stringArray(v.Export())
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("%s: %v", what, err)))
	}
	return result
}

// jsTypeName names an exported JavaScript value's type for an error message.
func jsTypeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null or undefined"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int64, float64, int, uint64:
		return "a number"
	case []interface{}:
		return "an array"
	case map[string]interface{}:
		return "an object"
	default:
		return fmt.Sprintf("a %T", v)
	}
}

// stringArg reads a function argument that names something: an address, an
// alias, an asset, a method, a path. JavaScript turns undefined and null into
// the words "undefined" and "null", which would then be looked up as an
// alias, so those are refused, as is an object or an array. A number is
// accepted, since an asset can be named by its ID.
func (a *API) stringArg(call goja.FunctionCall, index int) string {
	v := call.Arguments[index]
	switch exported := v.Export().(type) {
	case string:
		return exported
	case int64:
		if exported >= 0 {
			return strconv.FormatInt(exported, 10)
		}
	case float64:
		// A whole number names an asset by ID. NaN, Infinity and 1e21 would
		// become the words "NaN", "Infinity" and "1e+21".
		if exported >= 0 && exported == math.Trunc(exported) && exported <= maxSafeJSInteger {
			return strconv.FormatFloat(exported, 'f', 0, 64)
		}
	}
	panic(a.runtime.ToValue(fmt.Sprintf("argument %d is %s; a string is needed", index+1, jsTypeName(v.Export()))))
}

// pluginArg reads one argument for a plugin, which takes its arguments as
// text. A string, number, boolean or BigInt is passed as its text; undefined,
// null, an object or an array is refused, since those would arrive as the
// words "undefined", "null" and "[object Object]".
func (a *API) pluginArg(call goja.FunctionCall, index int) string {
	v := call.Arguments[index]
	switch v.Export().(type) {
	case string, bool, int64, float64, *big.Int:
		return v.String()
	default:
		panic(a.runtime.ToValue(fmt.Sprintf("plugin() argument %d is %s; pass text, a number or a boolean", index+1, jsTypeName(v.Export()))))
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
