// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package jsapi provides JavaScript API bindings for the aPlane engine.
//
// This package exposes engine functionality to JavaScript scripts running in
// the Goja runtime. Functions are organized into domain-specific files:
//   - api.go: Core API struct, registration, output, network/status, utilities
//   - accounts.go: Account queries, aliases, sets, signers
//   - assets.go: ASA info, cache, lifecycle
//   - transactions.go: Payment, transfer, keyreg, rekey operations
//   - atomic.go: Atomic transaction groups
//   - helpers.go: Type conversion utilities
package jsapi

import (
	"fmt"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// PluginExecutor defines the interface for executing plugin commands from JS.
type PluginExecutor interface {
	ExecutePlugin(name string, args []string) (success bool, message string, data interface{}, err error)
}

// API provides JavaScript bindings for the engine.
type API struct {
	engine         *engine.Engine
	runtime        *goja.Runtime
	verbose        bool
	output         func(string)
	pluginExecutor PluginExecutor
}

// NewAPI creates a new JavaScript API instance.
func NewAPI(eng *engine.Engine, verbose bool, output func(string)) *API {
	return &API{
		engine:  eng,
		verbose: verbose,
		output:  output,
	}
}

// SetPluginExecutor sets the plugin executor for the API.
func (a *API) SetPluginExecutor(executor PluginExecutor) {
	a.pluginExecutor = executor
}

// RegisterAll registers all API functions on the given Goja runtime.
func (a *API) RegisterAll(vm *goja.Runtime) error {
	a.runtime = vm

	// Helper to register and return error on failure
	set := func(name string, fn func(goja.FunctionCall) goja.Value) error {
		return vm.Set(name, fn)
	}

	// Standalone helpers (not methods on API)
	if err := vm.Set("algo", makeAlgoFunc(vm)); err != nil {
		return fmt.Errorf("failed to register algo: %w", err)
	}
	if err := vm.Set("microalgos", makeMicroalgosFunc(vm)); err != nil {
		return fmt.Errorf("failed to register microalgos: %w", err)
	}

	// Output functions
	if err := set("print", a.jsPrint); err != nil {
		return fmt.Errorf("failed to register print: %w", err)
	}
	if err := set("log", a.jsLog); err != nil {
		return fmt.Errorf("failed to register log: %w", err)
	}

	// Network/status functions
	if err := set("network", a.jsNetwork); err != nil {
		return fmt.Errorf("failed to register network: %w", err)
	}
	if err := set("status", a.jsStatus); err != nil {
		return fmt.Errorf("failed to register status: %w", err)
	}
	if err := set("connected", a.jsConnected); err != nil {
		return fmt.Errorf("failed to register connected: %w", err)
	}

	// Utility functions
	if err := set("waitForTx", a.jsWaitForTx); err != nil {
		return fmt.Errorf("failed to register waitForTx: %w", err)
	}
	if err := set("setWriteMode", a.jsSetWriteMode); err != nil {
		return fmt.Errorf("failed to register setWriteMode: %w", err)
	}
	if err := set("writeMode", a.jsWriteMode); err != nil {
		return fmt.Errorf("failed to register writeMode: %w", err)
	}
	if err := set("setVerbose", a.jsSetVerbose); err != nil {
		return fmt.Errorf("failed to register setVerbose: %w", err)
	}
	if err := set("setSimulate", a.jsSetSimulate); err != nil {
		return fmt.Errorf("failed to register setSimulate: %w", err)
	}
	if err := set("simulate", a.jsSimulate); err != nil {
		return fmt.Errorf("failed to register simulate: %w", err)
	}
	if err := set("plugin", a.jsPlugin); err != nil {
		return fmt.Errorf("failed to register plugin: %w", err)
	}

	// Account functions
	if err := set("balance", a.jsBalance); err != nil {
		return fmt.Errorf("failed to register balance: %w", err)
	}
	if err := set("accounts", a.jsAccounts); err != nil {
		return fmt.Errorf("failed to register accounts: %w", err)
	}
	if err := set("resolve", a.jsResolve); err != nil {
		return fmt.Errorf("failed to register resolve: %w", err)
	}
	if err := set("alias", a.jsAlias); err != nil {
		return fmt.Errorf("failed to register alias: %w", err)
	}
	if err := set("aliases", a.jsAliases); err != nil {
		return fmt.Errorf("failed to register aliases: %w", err)
	}
	if err := set("addAlias", a.jsAddAlias); err != nil {
		return fmt.Errorf("failed to register addAlias: %w", err)
	}
	if err := set("removeAlias", a.jsRemoveAlias); err != nil {
		return fmt.Errorf("failed to register removeAlias: %w", err)
	}
	if err := set("set", a.jsSet); err != nil {
		return fmt.Errorf("failed to register set: %w", err)
	}
	if err := set("sets", a.jsSets); err != nil {
		return fmt.Errorf("failed to register sets: %w", err)
	}
	if err := set("createSet", a.jsCreateSet); err != nil {
		return fmt.Errorf("failed to register createSet: %w", err)
	}
	if err := set("addToSet", a.jsAddToSet); err != nil {
		return fmt.Errorf("failed to register addToSet: %w", err)
	}
	if err := set("removeFromSet", a.jsRemoveFromSet); err != nil {
		return fmt.Errorf("failed to register removeFromSet: %w", err)
	}
	if err := set("deleteSet", a.jsDeleteSet); err != nil {
		return fmt.Errorf("failed to register deleteSet: %w", err)
	}
	if err := set("signers", a.jsSigners); err != nil {
		return fmt.Errorf("failed to register signers: %w", err)
	}
	if err := set("holders", a.jsHolders); err != nil {
		return fmt.Errorf("failed to register holders: %w", err)
	}
	if err := set("keys", a.jsKeys); err != nil {
		return fmt.Errorf("failed to register keys: %w", err)
	}
	if err := set("signableAddresses", a.jsSignableAddresses); err != nil {
		return fmt.Errorf("failed to register signableAddresses: %w", err)
	}
	if err := set("canSignFor", a.jsCanSignFor); err != nil {
		return fmt.Errorf("failed to register canSignFor: %w", err)
	}

	// Asset functions
	if err := set("assetInfo", a.jsAssetInfo); err != nil {
		return fmt.Errorf("failed to register assetInfo: %w", err)
	}
	if err := set("cachedAssets", a.jsCachedAssets); err != nil {
		return fmt.Errorf("failed to register cachedAssets: %w", err)
	}
	if err := set("cacheAsset", a.jsCacheAsset); err != nil {
		return fmt.Errorf("failed to register cacheAsset: %w", err)
	}
	if err := set("uncacheAsset", a.jsUncacheAsset); err != nil {
		return fmt.Errorf("failed to register uncacheAsset: %w", err)
	}
	if err := set("clearAssetCache", a.jsClearAssetCache); err != nil {
		return fmt.Errorf("failed to register clearAssetCache: %w", err)
	}
	if err := set("getAsaId", a.jsGetAsaId); err != nil {
		return fmt.Errorf("failed to register getAsaId: %w", err)
	}
	// Transaction functions
	if err := set("validate", a.jsValidate); err != nil {
		return fmt.Errorf("failed to register validate: %w", err)
	}
	if err := set("send", a.jsSend); err != nil {
		return fmt.Errorf("failed to register send: %w", err)
	}
	if err := set("sweep", a.jsSweep); err != nil {
		return fmt.Errorf("failed to register sweep: %w", err)
	}
	if err := set("sendAsset", a.jsSendAsset); err != nil {
		return fmt.Errorf("failed to register sendAsset: %w", err)
	}
	if err := set("optIn", a.jsOptIn); err != nil {
		return fmt.Errorf("failed to register optIn: %w", err)
	}
	if err := set("optOut", a.jsOptOut); err != nil {
		return fmt.Errorf("failed to register optOut: %w", err)
	}
	if err := set("keyreg", a.jsKeyreg); err != nil {
		return fmt.Errorf("failed to register keyreg: %w", err)
	}
	if err := set("participation", a.jsParticipation); err != nil {
		return fmt.Errorf("failed to register participation: %w", err)
	}
	if err := set("incentiveEligible", a.jsIncentiveEligible); err != nil {
		return fmt.Errorf("failed to register incentiveEligible: %w", err)
	}
	if err := set("rekey", a.jsRekey); err != nil {
		return fmt.Errorf("failed to register rekey: %w", err)
	}
	if err := set("unrekey", a.jsUnrekey); err != nil {
		return fmt.Errorf("failed to register unrekey: %w", err)
	}
	if err := set("isRekeyed", a.jsIsRekeyed); err != nil {
		return fmt.Errorf("failed to register isRekeyed: %w", err)
	}

	// Atomic transaction functions
	if err := set("atomicSend", a.jsAtomicSend); err != nil {
		return fmt.Errorf("failed to register atomicSend: %w", err)
	}
	if err := set("atomicSendAsset", a.jsAtomicSendAsset); err != nil {
		return fmt.Errorf("failed to register atomicSendAsset: %w", err)
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

	err := a.engine.WaitForConfirmation(txid, rounds)
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
// plugin(name, ...args) - Executes plugin and returns { success, message, data }
func (a *API) jsPlugin(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "plugin() requires at least a plugin/command name")
	if a.pluginExecutor == nil {
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
	success, message, data, err := a.pluginExecutor.ExecutePlugin(pluginName, args)
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

	return a.runtime.ToValue(result)
}
