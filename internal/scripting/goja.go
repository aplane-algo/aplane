// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package scripting

import (
	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/jsapi"
)

// GojaRunner implements Runner using the Goja JavaScript interpreter.
type GojaRunner struct {
	vm     *goja.Runtime
	api    *jsapi.API
	output func(string)
}

// NewGojaRunner creates a new Goja-based script runner.
// The runner is bound to the given Engine for API access.
func NewGojaRunner(eng *engine.Engine) *GojaRunner {
	r := &GojaRunner{
		output: func(s string) {}, // Default: discard output
	}

	// Create Goja runtime
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))

	// Ensure signer cache is populated for accounts() to show signable status
	eng.EnsureSignerCache()

	// Create API with output wrapper (so SetOutput works after creation)
	api := jsapi.NewAPI(eng, false, func(msg string) {
		r.output(msg)
	})
	if err := api.RegisterAll(vm); err != nil {
		// Registration errors are programming bugs, not runtime errors
		panic("failed to register JS API: " + err.Error())
	}

	r.vm = vm
	r.api = api

	return r
}

// Run executes JavaScript code and returns the result.
func (r *GojaRunner) Run(code string) (Result, error) {
	result, err := r.vm.RunString(code)
	if err != nil {
		// Convert Goja exceptions to regular errors with clean messages
		if jsErr, ok := err.(*goja.Exception); ok {
			// Use String() to get proper error message including stack trace info
			// Don't use Value().Export() as that returns map[] for Error objects
			return Result{}, &ScriptError{Message: jsErr.String()}
		}
		return Result{}, err
	}

	// Check for empty/void results
	if result == nil || goja.IsUndefined(result) || goja.IsNull(result) {
		return Result{IsEmpty: true}, nil
	}

	return Result{Value: result.Export()}, nil
}

// SetOutput sets the function used for print() and log() output.
func (r *GojaRunner) SetOutput(fn func(string)) {
	if fn == nil {
		r.output = func(s string) {}
	} else {
		r.output = fn
	}
}

// SetPluginExecutor sets the plugin executor for the plugin() JS function.
func (r *GojaRunner) SetPluginExecutor(executor jsapi.PluginExecutor) {
	r.api.SetPluginExecutor(executor)
}

// Interrupt stops the currently running script.
// Safe to call from another goroutine (e.g., for timeout enforcement).
func (r *GojaRunner) Interrupt() {
	r.vm.Interrupt("script interrupted")
}

// Runtime returns the underlying Goja runtime.
// Use sparingly - prefer the Runner interface for portability.
func (r *GojaRunner) Runtime() *goja.Runtime {
	return r.vm
}

// Compile-time interface check
var _ Runner = (*GojaRunner)(nil)
