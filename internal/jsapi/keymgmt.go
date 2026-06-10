// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

// JavaScript API functions for key management:
// - keyTypes(): list available key types from the signer
// - generateKey(keyType, params): generate a new signing key
// - deleteKey(address): delete a signing key

import (
	"fmt"

	"github.com/dop251/goja"
)

// jsKeyTypes returns available key types from the signer.
// keyTypes() - Returns array of key type objects
func (a *API) jsKeyTypes(call goja.FunctionCall) goja.Value {
	keyTypes, err := a.engine.ListKeyTypes(a.Context())
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("keyTypes() error: %v", err)))
	}

	result := make([]map[string]interface{}, len(keyTypes))
	for i, kt := range keyTypes {
		entry := map[string]interface{}{
			"keyType":           kt.KeyType,
			"family":            kt.Family,
			"displayName":       kt.DisplayName,
			"description":       kt.Description,
			"requiresLogicSig":  kt.RequiresLogicSig,
			"mnemonicWordCount": kt.MnemonicWordCount,
			"mnemonicImport":    kt.MnemonicImport,
			"mnemonicScheme":    kt.MnemonicScheme,
		}
		if len(kt.CreationParams) > 0 {
			params := make([]map[string]interface{}, len(kt.CreationParams))
			for j, p := range kt.CreationParams {
				params[j] = map[string]interface{}{
					"name":        p.Name,
					"label":       p.Label,
					"description": p.Description,
					"type":        p.Type,
					"required":    p.Required,
				}
				if p.Example != "" {
					params[j]["example"] = p.Example
				}
				if p.Placeholder != "" {
					params[j]["placeholder"] = p.Placeholder
				}
				if p.Default != "" {
					params[j]["default"] = p.Default
				}
			}
			entry["creationParams"] = params
		}
		if len(kt.RuntimeArgs) > 0 {
			runtimeArgs := make([]map[string]interface{}, len(kt.RuntimeArgs))
			for j, arg := range kt.RuntimeArgs {
				runtimeArgs[j] = map[string]interface{}{
					"name":        arg.Name,
					"label":       arg.Label,
					"description": arg.Description,
					"type":        arg.Type,
					"required":    arg.Required,
				}
				if arg.ByteLength > 0 {
					runtimeArgs[j]["byteLength"] = arg.ByteLength
				}
			}
			entry["runtimeArgs"] = runtimeArgs
		}
		result[i] = entry
	}

	return a.runtime.ToValue(result)
}

// jsGenerateKey generates a new signing key on the signer.
// generateKey(keyType) - Generate with defaults
// generateKey(keyType, {param: value, ...}) - Generate with parameters
func (a *API) jsGenerateKey(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "generateKey() requires a keyType argument")
	keyType := call.Arguments[0].String()

	params := make(map[string]string)
	if m := a.objectArg(call, 1, "generateKey()"); m != nil {
		for k, v := range m {
			params[k] = fmt.Sprintf("%v", v)
		}
	}

	result, err := a.engine.GenerateKey(a.Context(), keyType, params)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("generateKey() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"address": result.Address,
		"keyType": result.KeyType,
	})
}

// jsDeleteKey deletes a signing key from the signer.
// deleteKey(address) - Delete key by address or alias
func (a *API) jsDeleteKey(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "deleteKey() requires an address argument")
	addressOrAlias := call.Arguments[0].String()

	address, _, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("deleteKey() error resolving address: %v", err)))
	}

	if err := a.engine.DeleteKey(a.Context(), address); err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("deleteKey() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"address": address,
		"deleted": true,
	})
}
