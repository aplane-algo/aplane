// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

// JavaScript API functions for atomic transaction groups:
// - atomicSend: Send multiple ALGO payments atomically
// - atomicSendAsset: Send multiple ASA transfers atomically

import (
	"bytes"
	"fmt"
	"maps"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// jsAtomicSend sends multiple ALGO payments atomically.
// atomicSend(payments, options) - payments is array of {from, to, amount, note, lsigArgs}
func (a *API) jsAtomicSend(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "atomicSend() requires a payments array")
	paymentsRaw, ok := call.Arguments[0].Export().([]interface{})
	if !ok {
		panic(a.runtime.ToValue("atomicSend() requires a payments array"))
	}
	if len(paymentsRaw) == 0 {
		panic(a.runtime.ToValue("atomicSend() requires at least one payment"))
	}

	opts := a.parseAtomicOptions(call, "atomicSend()", "payment")

	payments := make([]engine.AtomicPaymentParams, len(paymentsRaw))
	senders := make([]string, len(paymentsRaw))
	lsigArgs := make([]map[string][]byte, len(paymentsRaw))
	for i, p := range paymentsRaw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: must be an object", i+1)))
		}
		a.refuseUnknownKeys(pm, fmt.Sprintf("atomicSend() payment %d key", i+1), "from", "to", "amount", "note", "lsigArgs")
		lsigArgs[i] = a.lsigArgsOption(pm, fmt.Sprintf("atomicSend() payment %d", i+1))

		from, ok := pm["from"].(string)
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: missing from field", i+1)))
		}
		to, ok := pm["to"].(string)
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: missing to field", i+1)))
		}
		amount, ok := pm["amount"]
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: missing amount field", i+1)))
		}

		var note string
		if n, ok := a.optionString(pm, "note", "atomicSend()"); ok {
			note = n
		}

		fromAddr, _, err := a.engine.ResolveAddress(from)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: error resolving from: %v", i+1, err)))
		}
		toAddr, _, err := a.engine.ResolveAddress(to)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: error resolving to: %v", i+1, err)))
		}

		amountVal, err := toUint64Interface(amount)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: invalid amount: %v", i+1, err)))
		}

		senders[i] = fromAddr
		payments[i] = engine.AtomicPaymentParams{
			From:   fromAddr,
			To:     toAddr,
			Amount: amountVal,
			Note:   note,
		}
	}

	args := a.atomicLsigArgs("atomicSend() payments", senders, lsigArgs)
	prep, err := a.engine.PrepareAtomicPayments(a.Context(), payments, engine.AtomicGroupParams{
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() error preparing transactions: %v", err)))
	}

	result, err := a.engine.SignAndSubmitAtomic(a.Context(), prep, args, opts.Wait)
	if err != nil {
		a.throwSubmitError(fmt.Errorf("atomicSend() error submitting transactions: %w", err))
	}

	txids := make([]interface{}, len(result.TxIDs))
	for i, id := range result.TxIDs {
		txids[i] = id
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txids":     txids,
		"confirmed": result.Confirmed,
	})
}

// jsAtomicSendAsset sends multiple ASA transfers atomically.
// atomicSendAsset(transfers, options) - transfers is array of {from, to, assetId, amount, note, lsigArgs}
func (a *API) jsAtomicSendAsset(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "atomicSendAsset() requires a transfers array")
	transfersRaw, ok := call.Arguments[0].Export().([]interface{})
	if !ok {
		panic(a.runtime.ToValue("atomicSendAsset() requires a transfers array"))
	}
	if len(transfersRaw) == 0 {
		panic(a.runtime.ToValue("atomicSendAsset() requires at least one transfer"))
	}

	opts := a.parseAtomicOptions(call, "atomicSendAsset()", "transfer")

	transfers := make([]engine.AtomicASAParams, len(transfersRaw))
	senders := make([]string, len(transfersRaw))
	lsigArgs := make([]map[string][]byte, len(transfersRaw))
	for i, t := range transfersRaw {
		tm, ok := t.(map[string]interface{})
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: must be an object", i+1)))
		}
		a.refuseUnknownKeys(tm, fmt.Sprintf("atomicSendAsset() transfer %d key", i+1), "from", "to", "assetId", "amount", "note", "lsigArgs")
		lsigArgs[i] = a.lsigArgsOption(tm, fmt.Sprintf("atomicSendAsset() transfer %d", i+1))

		from, ok := tm["from"].(string)
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: missing from field", i+1)))
		}
		to, ok := tm["to"].(string)
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: missing to field", i+1)))
		}
		assetID, ok := tm["assetId"]
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: missing assetId field", i+1)))
		}
		amount, ok := tm["amount"]
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: missing amount field", i+1)))
		}

		var note string
		if n, ok := a.optionString(tm, "note", "atomicSendAsset()"); ok {
			note = n
		}

		fromAddr, _, err := a.engine.ResolveAddress(from)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: error resolving from: %v", i+1, err)))
		}
		toAddr, _, err := a.engine.ResolveAddress(to)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: error resolving to: %v", i+1, err)))
		}

		assetIDVal, err := toUint64Interface(assetID)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: invalid assetId: %v", i+1, err)))
		}
		amountVal, err := toUint64Interface(amount)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: invalid amount: %v", i+1, err)))
		}

		senders[i] = fromAddr
		transfers[i] = engine.AtomicASAParams{
			From:    fromAddr,
			To:      toAddr,
			AssetID: assetIDVal,
			Amount:  amountVal,
			Note:    note,
		}
	}

	args := a.atomicLsigArgs("atomicSendAsset() transfers", senders, lsigArgs)
	prep, err := a.engine.PrepareAtomicASATransfers(a.Context(), transfers, engine.AtomicGroupParams{
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() error preparing transactions: %v", err)))
	}

	result, err := a.engine.SignAndSubmitAtomic(a.Context(), prep, args, opts.Wait)
	if err != nil {
		a.throwSubmitError(fmt.Errorf("atomicSendAsset() error submitting transactions: %w", err))
	}

	txids := make([]interface{}, len(result.TxIDs))
	for i, id := range result.TxIDs {
		txids[i] = id
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txids":     txids,
		"confirmed": result.Confirmed,
	})
}

// parseAtomicOptions reads an atomic call's {fee, wait}. lsigArgs goes on each
// payment instead: for the whole call it would reach every sender, and an
// account that takes no arguments refuses any.
func (a *API) parseAtomicOptions(call goja.FunctionCall, funcName, item string) txnOptions {
	m := a.objectArg(call, 1, funcName)
	if _, given := m["lsigArgs"]; given {
		panic(a.runtime.ToValue(fmt.Sprintf("%s option lsigArgs goes on each %s, for its sender", funcName, item)))
	}
	return a.feeWaitOptions(m, funcName, nil)
}

// atomicLsigArgs gives each payment's lsigArgs to its sender, senders[i]
// being payment i's. A sender's transactions all get the same arguments
// (engine.LsigArgs), so payments from one sender that give different ones are
// refused. One that gives none differs from one that gives some, which it
// would otherwise get.
func (a *API) atomicLsigArgs(what string, senders []string, args []map[string][]byte) engine.LsigArgs {
	bySender := make(map[string]map[string][]byte)
	first := make(map[string]int)
	for i, from := range senders {
		j, seen := first[from]
		if !seen {
			first[from] = i
			bySender[from] = args[i]
			continue
		}
		if !maps.EqualFunc(args[i], args[j], bytes.Equal) {
			panic(a.runtime.ToValue(fmt.Sprintf("%s %d and %d are both from %s and give different lsigArgs: a sender's transactions all get the same arguments", what, j+1, i+1, from)))
		}
	}
	return engine.NewLsigArgs(nil, bySender)
}
