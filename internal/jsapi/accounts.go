// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsapi

// JavaScript API functions for account operations:
// - Account queries (balance, accounts, resolve)
// - Aliases (alias, aliases, addAlias, removeAlias)
// - Sets (set, sets, createSet, addToSet, removeFromSet, deleteSet)
// - Signers (signers, holders, keys, signableAddresses, canSignFor)

import (
	"fmt"

	"github.com/dop251/goja"
)

// jsBalance returns balance info for an address or alias.
func (a *API) jsBalance(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "balance() requires an address or alias argument")
	addressOrAlias := call.Arguments[0].String()
	result, err := a.engine.GetBalance(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("balance() error: %v", err)))
	}

	// Build assets map
	assets := make(map[string]interface{})
	for _, asset := range result.Assets {
		assets[fmt.Sprintf("%d", asset.AssetID)] = map[string]interface{}{
			"amount":   asset.Amount,
			"unitName": asset.UnitName,
			"decimals": asset.Decimals,
			"frozen":   asset.IsFrozen,
		}
	}

	return a.runtime.ToValue(map[string]interface{}{
		"algo":       result.AlgoBalance,
		"assets":     assets,
		"address":    result.Address,
		"alias":      result.Alias,
		"minBalance": result.MinBalance,
		"authAddr":   result.AuthAddr,
	})
}

// jsAccounts returns all known accounts with balances.
func (a *API) jsAccounts(call goja.FunctionCall) goja.Value {
	accounts, err := a.engine.ListAccounts()
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("accounts() error: %v", err)))
	}

	result := make([]interface{}, len(accounts))
	for i, acc := range accounts {
		result[i] = map[string]interface{}{
			"address":    acc.Address,
			"alias":      acc.Alias,
			"isSignable": acc.IsSignable,
			"keyType":    acc.KeyType,
		}
	}
	return a.runtime.ToValue(result)
}

// jsResolve resolves an address or alias to canonical form.
func (a *API) jsResolve(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "resolve() requires an address or alias argument")
	addressOrAlias := call.Arguments[0].String()

	address, alias, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("resolve() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"address": address,
		"alias":   alias,
	})
}

// jsAlias returns the address for an alias.
func (a *API) jsAlias(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "alias() requires a name argument")
	name := call.Arguments[0].String()
	info := a.engine.GetAlias(name)
	if info == nil {
		return goja.Null()
	}
	return a.runtime.ToValue(info.Address)
}

// jsAliases returns all defined aliases.
func (a *API) jsAliases(call goja.FunctionCall) goja.Value {
	result := a.engine.ListAliases()
	aliases := make(map[string]interface{})
	for _, a := range result.Aliases {
		aliases[a.Name] = a.Address
	}
	return a.runtime.ToValue(aliases)
}

// jsAddAlias adds or updates an alias.
// addAlias(name, address) - Returns {name, address, created}
func (a *API) jsAddAlias(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "addAlias() requires name and address arguments")
	name := call.Arguments[0].String()
	address := call.Arguments[1].String()

	result, err := a.engine.AddAlias(name, address)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("addAlias() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"name":    result.Name,
		"address": result.Address,
		"created": !result.WasUpdated,
	})
}

// jsRemoveAlias removes an alias.
// removeAlias(name) - Returns the address that was removed
func (a *API) jsRemoveAlias(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "removeAlias() requires a name argument")
	name := call.Arguments[0].String()

	address, err := a.engine.RemoveAlias(name)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("removeAlias() error: %v", err)))
	}

	return a.runtime.ToValue(address)
}

// jsSet returns addresses in a set.
func (a *API) jsSet(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "set() requires a name argument")
	name := call.Arguments[0].String()
	info := a.engine.GetSet(name)
	if info == nil {
		return goja.Null()
	}

	result := make([]interface{}, len(info.Addresses))
	for i, addr := range info.Addresses {
		result[i] = addr
	}
	return a.runtime.ToValue(result)
}

// jsSets returns all set names.
func (a *API) jsSets(call goja.FunctionCall) goja.Value {
	result := a.engine.ListSets()
	names := make([]interface{}, len(result.Sets))
	for i, s := range result.Sets {
		names[i] = s.Name
	}
	return a.runtime.ToValue(names)
}

// jsCreateSet creates or replaces a set with the given addresses.
func (a *API) jsCreateSet(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "createSet() requires name and addresses arguments")
	name := call.Arguments[0].String()
	addresses := toStringArray(call.Arguments[1])

	result, err := a.engine.AddSet(name, addresses)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("createSet() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"name":    result.Name,
		"count":   len(result.Addresses),
		"updated": result.WasUpdated,
	})
}

// jsAddToSet adds addresses to an existing set (creates if doesn't exist).
func (a *API) jsAddToSet(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "addToSet() requires name and addresses arguments")
	name := call.Arguments[0].String()
	addresses := toStringArray(call.Arguments[1])

	result, err := a.engine.AddToSet(name, addresses)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("addToSet() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"name":     result.Name,
		"count":    len(result.Addresses),
		"added":    len(result.Addresses) - result.OldCount,
		"oldCount": result.OldCount,
	})
}

// jsRemoveFromSet removes addresses from a set.
func (a *API) jsRemoveFromSet(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "removeFromSet() requires name and addresses arguments")
	name := call.Arguments[0].String()
	addresses := toStringArray(call.Arguments[1])

	result, err := a.engine.RemoveFromSet(name, addresses)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("removeFromSet() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"name":    result.Name,
		"count":   len(result.Addresses),
		"removed": result.OldCount - len(result.Addresses),
	})
}

// jsDeleteSet deletes a set entirely.
func (a *API) jsDeleteSet(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "deleteSet() requires a name argument")
	name := call.Arguments[0].String()

	count, err := a.engine.RemoveSet(name)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("deleteSet() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"name":    name,
		"deleted": count,
	})
}

// jsSigners returns signer addresses.
// signers() - returns map of all signers {addr: keyType}
// signers(addresses) - returns array of addresses that are signers (filter mode)
func (a *API) jsSigners(call goja.FunctionCall) goja.Value {
	allSigners := a.engine.ListSigners()

	// No arguments: return all signers as map
	if len(call.Arguments) == 0 {
		result := make(map[string]interface{}, len(allSigners))
		for addr, keyType := range allSigners {
			result[addr] = keyType
		}
		return a.runtime.ToValue(result)
	}

	// With array argument: filter to only signers
	addresses := toStringArray(call.Arguments[0])
	result := make([]interface{}, 0)
	for _, addr := range addresses {
		if _, isSigner := allSigners[addr]; isSigner {
			result = append(result, addr)
		}
	}
	return a.runtime.ToValue(result)
}

// jsHolders returns addresses with non-zero balance of an asset.
// holders() or holders("algo") - returns all ALGO holders
// holders("usdc") or holders(31566704) - returns all ASA holders
// holders(addresses, "algo") - returns subset of addresses that hold ALGO (filter mode)
// holders(addresses, "usdc") - returns subset of addresses that hold USDC (filter mode)
func (a *API) jsHolders(call goja.FunctionCall) goja.Value {
	// Check if first argument is an array (filter mode)
	if len(call.Arguments) >= 1 {
		if arr, ok := call.Arguments[0].Export().([]interface{}); ok {
			// Filter mode: holders(addresses, asset)
			assetRef := "algo"
			if len(call.Arguments) >= 2 {
				assetRef = call.Arguments[1].String()
			}

			allHolders, err := a.engine.GetHolders(assetRef)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("holders() error: %v", err)))
			}

			// Build lookup set
			holderSet := make(map[string]bool, len(allHolders))
			for _, addr := range allHolders {
				holderSet[addr] = true
			}

			// Filter input addresses
			result := make([]interface{}, 0)
			for _, item := range arr {
				addr, ok := item.(string)
				if ok && holderSet[addr] {
					result = append(result, addr)
				}
			}
			return a.runtime.ToValue(result)
		}
	}

	// Normal mode: holders() or holders(asset)
	assetRef := "algo"
	if len(call.Arguments) >= 1 {
		assetRef = call.Arguments[0].String()
	}

	holders, err := a.engine.GetHolders(assetRef)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("holders() error: %v", err)))
	}

	result := make([]interface{}, len(holders))
	for i, addr := range holders {
		result[i] = addr
	}
	return a.runtime.ToValue(result)
}

// jsKeys returns list of signing keys from Signer.
// keys() - Returns array of key info objects
func (a *API) jsKeys(call goja.FunctionCall) goja.Value {
	keys, err := a.engine.ListKeys()
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("keys() error: %v", err)))
	}

	result := make([]interface{}, len(keys))
	for i, k := range keys {
		result[i] = map[string]interface{}{
			"address": k.Address,
			"keyType": k.KeyType,
		}
	}
	return a.runtime.ToValue(result)
}

// jsSignableAddresses returns all addresses we can sign for.
// signableAddresses() - Returns array of address strings
func (a *API) jsSignableAddresses(call goja.FunctionCall) goja.Value {
	addresses := a.engine.GetSignableAddresses()

	result := make([]interface{}, len(addresses))
	for i, addr := range addresses {
		result[i] = addr
	}
	return a.runtime.ToValue(result)
}

// jsCanSignFor checks if we can sign for an address.
// canSignFor(address) - Returns {canSign: bool, isLsig: bool}
func (a *API) jsCanSignFor(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "canSignFor() requires an address argument")
	addressOrAlias := call.Arguments[0].String()
	address, _, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("canSignFor() error resolving address: %v", err)))
	}

	canSign, isLsig := a.engine.CanSignForAddress(address)

	return a.runtime.ToValue(map[string]interface{}{
		"canSign": canSign,
		"isLsig":  isLsig,
	})
}
