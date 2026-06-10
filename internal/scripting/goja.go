// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package scripting

import (
	"context"
	"fmt"
	"sync"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/jsapi"
)

// GojaRunner implements Runner using the Goja JavaScript interpreter.
type GojaRunner struct {
	vm             *goja.Runtime
	api            *jsapi.API
	mu             sync.RWMutex
	output         func(string)
	startupWarning string
	warningEmitted bool
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

	// Best-effort cache warmup for accounts(); surface failures once on output instead of silently dropping them.
	if err := eng.EnsureSignerCache(context.Background()); err != nil {
		r.startupWarning = fmt.Sprintf("Warning: failed to warm signer cache: %v", err)
	}

	// Create API with output wrapper (so SetOutput works after creation)
	api := jsapi.NewAPI(eng, false, func(msg string) {
		r.getOutput()(msg)
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
func (r *GojaRunner) Run(code string) (result Result, err error) {
	return r.RunWithContext(context.Background(), code)
}

// RunWithContext executes JavaScript code and makes ctx available to host-side
// API calls made by the script.
func (r *GojaRunner) RunWithContext(ctx context.Context, code string) (result Result, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.emitStartupWarning()
	restoreCtx := r.api.SetContext(ctx)
	defer restoreCtx()

	state := r.modeState()
	writeMode := state.writeMode
	verbose := state.verbose
	simulate := state.simulate
	defer r.api.RestoreModeState(writeMode, verbose, simulate)

	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}

		result = Result{}
		switch v := recovered.(type) {
		case *goja.Exception:
			err = &RunnerError{Message: v.String()}
		case goja.Value:
			err = &RunnerError{Message: v.String()}
		case error:
			err = fmt.Errorf("script panic: %w", v)
		default:
			err = fmt.Errorf("script panic: %v", v)
		}
	}()

	value, err := r.vm.RunString(code)
	if err != nil {
		// Convert Goja exceptions to regular errors with clean messages
		if jsErr, ok := err.(*goja.Exception); ok {
			// Use String() to get proper error message including stack trace info
			// Don't use Value().Export() as that returns map[] for Error objects
			return Result{}, &RunnerError{Message: jsErr.String()}
		}
		return Result{}, err
	}

	// Check for empty/void results
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return Result{IsEmpty: true}, nil
	}

	return Result{Value: value.Export()}, nil
}

// SetOutput sets the function used for print() and log() output.
func (r *GojaRunner) SetOutput(fn func(string)) {
	var warning string
	var output func(string)

	r.mu.Lock()
	if fn == nil {
		r.output = func(s string) {}
	} else {
		r.output = fn
	}
	if r.startupWarning != "" && !r.warningEmitted {
		warning = r.startupWarning
		output = r.output
		r.warningEmitted = true
	}
	r.mu.Unlock()

	if warning != "" {
		output(warning)
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

type runnerModeState struct {
	writeMode bool
	verbose   bool
	simulate  bool
}

func (r *GojaRunner) modeState() runnerModeState {
	eng := r.api.Engine()
	return runnerModeState{
		writeMode: eng.GetWriteMode(),
		verbose:   r.api.Verbose(),
		simulate:  eng.GetSimulate(),
	}
}

func (r *GojaRunner) getOutput() func(string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.output
}

func (r *GojaRunner) emitStartupWarning() {
	var warning string
	var output func(string)

	r.mu.Lock()
	if r.startupWarning != "" && !r.warningEmitted {
		warning = r.startupWarning
		output = r.output
		r.warningEmitted = true
	}
	r.mu.Unlock()

	if warning != "" {
		output(warning)
	}
}

// Compile-time interface check
var _ Runner = (*GojaRunner)(nil)
