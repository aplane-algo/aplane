// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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
	paymentsRaw, ok := call.Arguments[0].Export().([]interface{})
	if !ok {
		panic(a.runtime.ToValue("atomicSend() requires a payments array"))
	}
	if len(paymentsRaw) == 0 {
		panic(a.runtime.ToValue("atomicSend() requires at least one payment"))
	}

	opts := a.parseTxnOptions(call, 1, "atomicSend()")

	payments := make([]engine.AtomicPaymentParams, len(paymentsRaw))
	for i, p := range paymentsRaw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() payment %d: must be an object", i+1)))
		}

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

	prep, err := a.engine.PrepareAtomicPayments(a.Context(), payments, engine.AtomicGroupParams{
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSend() error preparing transactions: %v", err)))
	}

	result, err := a.engine.SignAndSubmitAtomic(a.Context(), prep, opts.Wait)
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
	transfersRaw, ok := call.Arguments[0].Export().([]interface{})
	if !ok {
		panic(a.runtime.ToValue("atomicSendAsset() requires a transfers array"))
	}
	if len(transfersRaw) == 0 {
		panic(a.runtime.ToValue("atomicSendAsset() requires at least one transfer"))
	}

	opts := a.parseTxnOptions(call, 1, "atomicSendAsset()")

	transfers := make([]engine.AtomicASAParams, len(transfersRaw))
	for i, t := range transfersRaw {
		tm, ok := t.(map[string]interface{})
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() transfer %d: must be an object", i+1)))
		}

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

	prep, err := a.engine.PrepareAtomicASATransfers(a.Context(), transfers, engine.AtomicGroupParams{
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("atomicSendAsset() error preparing transactions: %v", err)))
	}

	result, err := a.engine.SignAndSubmitAtomic(a.Context(), prep, opts.Wait)
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
