// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsapi provides JavaScript API bindings for the APlane engine.
//
// This package exposes engine functionality to JavaScript scripts running in
// the Goja runtime. Functions are organized into domain-specific files:
//   - api.go: Core API struct, registration, output, network/status, utilities
//   - accounts.go: Account queries, aliases, sets, signers
//   - apps.go: Application state reads and application call execution
//   - assets.go: ASA info, cache, lifecycle
//   - transactions.go: Payment, transfer, keyreg, rekey operations
//   - atomic.go: Atomic transaction groups
//   - helpers.go: Type conversion utilities
package jsapi

import (
	"context"
	"fmt"
	"sync"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// PluginExecutor defines the interface for executing plugin commands from JS.
type PluginExecutor interface {
	ExecutePlugin(name string, args []string) (success bool, message string, data interface{}, presentation interface{}, err error)
}

// API provides JavaScript bindings for the engine.
type API struct {
	engine         *engine.Engine
	runtime        *goja.Runtime
	verbose        bool
	output         func(string)
	pluginMu       sync.RWMutex
	pluginExecutor PluginExecutor
	ctxMu          sync.RWMutex
	ctx            context.Context
}

// NewAPI creates a new JavaScript API instance.
func NewAPI(eng *engine.Engine, verbose bool, output func(string)) *API {
	return &API{
		engine:  eng,
		verbose: verbose,
		output:  output,
		ctx:     context.Background(),
	}
}

// Context returns the caller context for host-side work triggered by JS.
func (a *API) Context() context.Context {
	a.ctxMu.RLock()
	defer a.ctxMu.RUnlock()
	if a.ctx == nil {
		return context.Background()
	}
	return a.ctx
}

// SetContext sets the caller context for one script execution and returns a
// cleanup function that restores the previous value.
func (a *API) SetContext(ctx context.Context) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	a.ctxMu.Lock()
	prev := a.ctx
	a.ctx = ctx
	a.ctxMu.Unlock()
	return func() {
		a.ctxMu.Lock()
		a.ctx = prev
		a.ctxMu.Unlock()
	}
}

// SetPluginExecutor sets the plugin executor for the API.
func (a *API) SetPluginExecutor(executor PluginExecutor) {
	a.pluginMu.Lock()
	defer a.pluginMu.Unlock()
	a.pluginExecutor = executor
}

func (a *API) getPluginExecutor() PluginExecutor {
	a.pluginMu.RLock()
	defer a.pluginMu.RUnlock()
	return a.pluginExecutor
}

// Engine returns the underlying engine bound to this API.
func (a *API) Engine() *engine.Engine {
	return a.engine
}

// Verbose returns the current JS-side verbose flag used by log().
func (a *API) Verbose() bool {
	return a.verbose
}

// RestoreModeState resets engine and JS mode flags after a script run.
func (a *API) RestoreModeState(writeMode, verbose, simulate bool) {
	a.engine.SetWriteMode(writeMode)
	a.engine.SetVerbose(verbose)
	a.engine.SetSimulate(simulate)
	a.verbose = verbose
}

// RegisterAll registers all API functions on the given Goja runtime.
func (a *API) RegisterAll(vm *goja.Runtime) error {
	a.runtime = vm

	type binding struct {
		name string
		fn   func(goja.FunctionCall) goja.Value
	}

	bindings := []binding{
		// Standalone helpers.
		{"algo", makeAlgoFunc(vm)},
		{"microalgos", makeMicroalgosFunc(vm)},

		// Output functions.
		{"print", a.jsPrint},
		{"log", a.jsLog},

		// Network/status functions.
		{"network", a.jsNetwork},
		{"status", a.jsStatus},
		{"connected", a.jsConnected},

		// Utility functions.
		{"waitForTx", a.jsWaitForTx},
		{"setWriteMode", a.jsSetWriteMode},
		{"writeMode", a.jsWriteMode},
		{"setVerbose", a.jsSetVerbose},
		{"setSimulate", a.jsSetSimulate},
		{"simulate", a.jsSimulate},
		{"plugin", a.jsPlugin},

		// Account functions.
		{"balance", a.jsBalance},
		{"accounts", a.jsAccounts},
		{"resolve", a.jsResolve},
		{"alias", a.jsAlias},
		{"aliases", a.jsAliases},
		{"addAlias", a.jsAddAlias},
		{"removeAlias", a.jsRemoveAlias},
		{"set", a.jsSet},
		{"sets", a.jsSets},
		{"createSet", a.jsCreateSet},
		{"addToSet", a.jsAddToSet},
		{"removeFromSet", a.jsRemoveFromSet},
		{"deleteSet", a.jsDeleteSet},
		{"signers", a.jsSigners},
		{"holders", a.jsHolders},
		{"keys", a.jsKeys},
		{"signableAddresses", a.jsSignableAddresses},
		{"canSignFor", a.jsCanSignFor},

		// Asset functions.
		{"assetInfo", a.jsAssetInfo},
		{"cachedAssets", a.jsCachedAssets},
		{"cacheAsset", a.jsCacheAsset},
		{"uncacheAsset", a.jsUncacheAsset},
		{"clearAssetCache", a.jsClearAssetCache},
		{"getAsaId", a.jsGetAsaId},

		// Application functions.
		{"appDeploy", a.jsAppDeploy},
		{"appInfo", a.jsAppInfo},
		{"appGlobal", a.jsAppGlobal},
		{"appLocal", a.jsAppLocal},
		{"appBox", a.jsAppBox},
		{"appBoxes", a.jsAppBoxes},
		{"appCallRaw", a.jsAppCallRaw},
		{"appCall", a.jsAppCall},

		// Transaction functions.
		{"validate", a.jsValidate},
		{"send", a.jsSend},
		{"sweep", a.jsSweep},
		{"sendAsset", a.jsSendAsset},
		{"optIn", a.jsOptIn},
		{"optOut", a.jsOptOut},
		{"keyreg", a.jsKeyreg},
		{"participation", a.jsParticipation},
		{"incentiveEligible", a.jsIncentiveEligible},
		{"rekey", a.jsRekey},
		{"unrekey", a.jsUnrekey},
		{"isRekeyed", a.jsIsRekeyed},
		{"close", a.jsClose},
		{"sign", a.jsSign},
		{"plan", a.jsPlan},

		// Key management functions.
		{"keyTypes", a.jsKeyTypes},
		{"generateKey", a.jsGenerateKey},
		{"deleteKey", a.jsDeleteKey},

		// Atomic transaction functions.
		{"atomicSend", a.jsAtomicSend},
		{"atomicSendAsset", a.jsAtomicSendAsset},
	}

	for _, b := range bindings {
		if err := vm.Set(b.name, b.fn); err != nil {
			return fmt.Errorf("failed to register %s: %w", b.name, err)
		}
	}

	return nil
}

// output helper for internal use.
func (a *API) outputMsg(msg string) {
	if a.output != nil {
		a.output(msg)
	} else {
		fmt.Println(msg)
	}
}

// jsPrint outputs a message to the console.
func (a *API) jsPrint(call goja.FunctionCall) goja.Value {
	args := make([]interface{}, len(call.Arguments))
	for i, arg := range call.Arguments {
		args[i] = arg.Export()
	}
	msg := fmt.Sprint(args...)
	a.outputMsg(msg)
	return goja.Undefined()
}

// jsLog outputs a debug message (only in verbose mode).
func (a *API) jsLog(call goja.FunctionCall) goja.Value {
	if !a.verbose {
		return goja.Undefined()
	}
	args := make([]interface{}, len(call.Arguments))
	for i, arg := range call.Arguments {
		args[i] = arg.Export()
	}
	msg := fmt.Sprint(args...)
	a.outputMsg("[debug] " + msg)
	return goja.Undefined()
}

// jsNetwork returns the current network name.
func (a *API) jsNetwork(call goja.FunctionCall) goja.Value {
	return a.runtime.ToValue(a.engine.GetNetwork())
}

// jsStatus returns connection status info.
func (a *API) jsStatus(call goja.FunctionCall) goja.Value {
	status := a.engine.GetStatus()
	return a.runtime.ToValue(map[string]interface{}{
		"network":     status.Network,
		"connected":   status.IsConnected,
		"target":      status.ConnectionTarget,
		"signingMode": status.SigningMode,
		"writeMode":   status.WriteMode,
		"simulate":    a.engine.GetSimulate(),
	})
}

// jsConnected returns true if connected to Signer.
func (a *API) jsConnected(call goja.FunctionCall) goja.Value {
	status := a.engine.GetStatus()
	return a.runtime.ToValue(status.IsConnected)
}

// jsWaitForTx waits for a transaction to be confirmed.
// waitForTx(txid, rounds) - Waits up to 'rounds' for confirmation
func (a *API) jsWaitForTx(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "waitForTx() requires a txid argument")
	txid := call.Arguments[0].String()

	var rounds uint64 = 5 // Default 5 rounds
	if len(call.Arguments) > 1 {
		rounds = toUint64(a.runtime, call.Arguments[1])
	}

	result, err := a.engine.WaitForConfirmationResult(a.Context(), txid, rounds)
	if result != nil && result.Output != "" {
		a.outputMsg(result.Output)
	}
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("waitForTx() error: %v", err)))
	}

	return a.runtime.ToValue(true)
}

// jsSetWriteMode enables or disables transaction JSON writing.
// setWriteMode(enabled) - Sets write mode
func (a *API) jsSetWriteMode(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "setWriteMode() requires a boolean argument")
	enabled := call.Arguments[0].ToBoolean()
	a.engine.SetWriteMode(enabled)

	return goja.Undefined()
}

// jsWriteMode returns the current write mode setting.
// writeMode() - Returns boolean
func (a *API) jsWriteMode(call goja.FunctionCall) goja.Value {
	return a.runtime.ToValue(a.engine.GetWriteMode())
}

// jsSetVerbose enables or disables verbose output.
// setVerbose(enabled) - Sets verbose mode
func (a *API) jsSetVerbose(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "setVerbose() requires a boolean argument")
	enabled := call.Arguments[0].ToBoolean()
	a.engine.SetVerbose(enabled)
	a.verbose = enabled

	return goja.Undefined()
}

// jsSetSimulate enables or disables transaction simulation mode.
// setSimulate(enabled) - Sets simulate mode
func (a *API) jsSetSimulate(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "setSimulate() requires a boolean argument")
	enabled := call.Arguments[0].ToBoolean()
	a.engine.SetSimulate(enabled)

	return goja.Undefined()
}

// jsSimulate returns the current simulate mode setting.
// simulate() - Returns boolean
func (a *API) jsSimulate(call goja.FunctionCall) goja.Value {
	return a.runtime.ToValue(a.engine.GetSimulate())
}

// jsPlugin executes an external plugin command.
// plugin(name, ...args) - Executes plugin and returns { success, message, data, presentation }
func (a *API) jsPlugin(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "plugin() requires at least a plugin/command name")
	executor := a.getPluginExecutor()
	if executor == nil {
		panic(a.runtime.ToValue("plugin() is not available (no plugin executor configured)"))
	}

	// First argument is the plugin/command name
	pluginName := call.Arguments[0].String()

	// Remaining arguments are passed to the plugin
	args := make([]string, len(call.Arguments)-1)
	for i := 1; i < len(call.Arguments); i++ {
		args[i-1] = call.Arguments[i].String()
	}

	// Execute the plugin
	success, message, data, presentation, err := executor.ExecutePlugin(pluginName, args)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("plugin() error: %v", err)))
	}

	// Return result object
	result := map[string]interface{}{
		"success": success,
		"message": message,
	}
	if data != nil {
		result["data"] = data
	}
	if presentation != nil {
		result["presentation"] = presentation
	}

	return a.runtime.ToValue(result)
}
