// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsapi

// JavaScript API functions for atomic transaction groups:
// - atomicSend: Send multiple ALGO payments atomically
// - atomicSendAsset: Send multiple ASA transfers atomically

import (
	"fmt"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// jsAtomicSend sends multiple ALGO payments atomically.
// atomicSend(payments, options) - payments is array of {from, to, amount, note}
func (a *API) jsAtomicSend(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "atomicSend() requires a payments array")
	paymentsRaw := call.Arguments[0].Export().([]interface{})
	if len(paymentsRaw) == 0 {
		panic(a.runtime.ToValue("atomicSend() requires at least one payment"))
	}

	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		opts := call.Arguments[1].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	payments := make([]engine.AtomicPaymentParams, len(paymentsRaw))
	for i, p := range paymentsRaw {
		pm := p.(map[string]interface{})

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
		if n, ok := pm["note"].(string); ok {
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

		payments[i] = engine.AtomicPaymentParams{
			From:   fromAddr,
			To:     toAddr,
			Amount: amountVal,
			Note:   note,
		}
	}

	prep, err := a.engine.PrepareAtomicPayments(payments, engine.AtomicGroupParams{
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() error preparing transactions: %v", err)))
	}

	result, err := a.engine.SignAndSubmitAtomic(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() error submitting transactions: %v", err)))
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
// atomicSendAsset(transfers, options) - transfers is array of {from, to, assetId, amount, note}
func (a *API) jsAtomicSendAsset(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "atomicSendAsset() requires a transfers array")
	transfersRaw := call.Arguments[0].Export().([]interface{})
	if len(transfersRaw) == 0 {
		panic(a.runtime.ToValue("atomicSendAsset() requires at least one transfer"))
	}

	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		opts := call.Arguments[1].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	transfers := make([]engine.AtomicASAParams, len(transfersRaw))
	for i, t := range transfersRaw {
		tm := t.(map[string]interface{})

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
		if n, ok := tm["note"].(string); ok {
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

		transfers[i] = engine.AtomicASAParams{
			From:    fromAddr,
			To:      toAddr,
			AssetID: assetIDVal,
			Amount:  amountVal,
			Note:    note,
		}
	}

	prep, err := a.engine.PrepareAtomicASATransfers(transfers, engine.AtomicGroupParams{
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() error preparing transactions: %v", err)))
	}

	result, err := a.engine.SignAndSubmitAtomic(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() error submitting transactions: %v", err)))
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
