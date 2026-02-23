// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsapi

// JavaScript API functions for transaction operations:
// - ALGO transfers (send, validate, sweep)
// - ASA transfers (sendAsset, optIn, optOut)
// - Key registration (keyreg, participation, incentiveEligible)
// - Rekey operations (rekey, unrekey, isRekeyed)

import (
	"fmt"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// jsValidate validates signing capability by sending 0 ALGO to self.
func (a *API) jsValidate(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "validate() requires an address or alias argument")
	addressOrAlias := call.Arguments[0].String()

	addr, _, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("validate() error resolving address: %v", err)))
	}

	prep, _, err := a.engine.PreparePayment(engine.SendPaymentParams{
		From:   addr,
		To:     addr,
		Amount: 0,
		Note:   "validate",
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("validate() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, true)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("validate() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
		"address":   addr,
	})
}

// jsSend sends ALGO from one account to another.
func (a *API) jsSend(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 3, "send() requires from, to, and amount arguments")
	from := call.Arguments[0].String()
	to := call.Arguments[1].String()
	amount := toUint64(a.runtime, call.Arguments[2])

	var note string
	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 3 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
		opts := call.Arguments[3].Export().(map[string]interface{})
		if n, ok := opts["note"].(string); ok {
			note = n
		}
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("send() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PreparePayment(engine.SendPaymentParams{
		From:       fromAddr,
		To:         toAddr,
		Amount:     amount,
		Note:       note,
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error submitting transaction: %v", err)))
	}

	// Write transaction JSON if write mode is enabled
	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsSweep closes an account, sending all funds to a destination.
func (a *API) jsSweep(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "sweep() requires from and to arguments")
	from := call.Arguments[0].String()
	to := call.Arguments[1].String()

	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		opts := call.Arguments[2].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("sweep() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareClose(engine.CloseAccountParams{
		From:       fromAddr,
		CloseTo:    toAddr,
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error submitting transaction: %v", err)))
	}

	// Write transaction JSON if write mode is enabled
	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsSendAsset sends an ASA from one account to another.
func (a *API) jsSendAsset(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 4, "sendAsset() requires from, to, assetId, and amount arguments")
	from := call.Arguments[0].String()
	to := call.Arguments[1].String()
	assetID := toUint64(a.runtime, call.Arguments[2])
	amount := toUint64(a.runtime, call.Arguments[3])

	var note string
	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 4 && !goja.IsUndefined(call.Arguments[4]) && !goja.IsNull(call.Arguments[4]) {
		opts := call.Arguments[4].Export().(map[string]interface{})
		if n, ok := opts["note"].(string); ok {
			note = n
		}
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareASATransfer(engine.SendASAParams{
		From:       fromAddr,
		To:         toAddr,
		AssetID:    assetID,
		Amount:     amount,
		Note:       note,
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error submitting transaction: %v", err)))
	}

	// Write transaction JSON if write mode is enabled
	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsOptIn opts an account into an ASA.
func (a *API) jsOptIn(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "optIn() requires account and assetId arguments")
	account := call.Arguments[0].String()
	assetID := toUint64(a.runtime, call.Arguments[1])

	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		opts := call.Arguments[2].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("optIn() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	accountAddr, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optIn() error resolving account: %v", err)))
	}

	prep, err := a.engine.PrepareOptIn(engine.OptInParams{
		Account:    accountAddr,
		AssetID:    assetID,
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optIn() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optIn() error submitting transaction: %v", err)))
	}

	// Write transaction JSON if write mode is enabled
	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsOptOut opts an account out of an ASA.
func (a *API) jsOptOut(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "optOut() requires account and assetId arguments")
	account := call.Arguments[0].String()
	assetID := toUint64(a.runtime, call.Arguments[1])

	var closeTo string
	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		arg2 := call.Arguments[2].Export()
		if s, ok := arg2.(string); ok {
			closeTo = s
		} else if opts, ok := arg2.(map[string]interface{}); ok {
			if f, ok := opts["fee"]; ok {
				var err error
				fee, err = toUint64Interface(f)
				if err != nil {
					panic(a.runtime.ToValue(fmt.Sprintf("optOut() invalid fee: %v", err)))
				}
				useFlatFee = true
			}
			if w, ok := opts["wait"].(bool); ok {
				wait = w
			}
		}
	}

	if len(call.Arguments) > 3 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
		opts := call.Arguments[3].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("optOut() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	accountAddr, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optOut() error resolving account: %v", err)))
	}

	closeToAddr := ""
	if closeTo != "" {
		closeToAddr, _, err = a.engine.ResolveAddress(closeTo)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("optOut() error resolving closeTo: %v", err)))
		}
	}

	prep, _, err := a.engine.PrepareOptOut(engine.OptOutParams{
		Account:    accountAddr,
		AssetID:    assetID,
		CloseTo:    closeToAddr,
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optOut() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optOut() error submitting transaction: %v", err)))
	}

	// Write transaction JSON if write mode is enabled
	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsKeyreg marks an account online or offline for consensus participation.
// keyreg(account, "offline") - Mark account offline
// keyreg(account, "online", { votekey, selkey, sproofkey, votefirst, votelast, keydilution }) - Mark online
func (a *API) jsKeyreg(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "keyreg() requires account and mode arguments")
	account := call.Arguments[0].String()
	mode := call.Arguments[1].String()

	if mode != "online" && mode != "offline" {
		panic(a.runtime.ToValue("keyreg() mode must be 'online' or 'offline'"))
	}

	accountAddr, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("keyreg() error resolving account: %v", err)))
	}

	params := engine.KeyRegParams{
		Account: accountAddr,
		Mode:    mode,
	}

	// For online mode, parse participation keys from options
	if mode == "online" {
		if len(call.Arguments) < 3 {
			panic(a.runtime.ToValue("keyreg() online mode requires options with participation keys"))
		}
		opts := call.Arguments[2].Export().(map[string]interface{})

		if v, ok := opts["votekey"].(string); ok {
			params.VoteKey = v
		}
		if v, ok := opts["selkey"].(string); ok {
			params.SelectionKey = v
		}
		if v, ok := opts["sproofkey"].(string); ok {
			params.StateProofKey = v
		}
		if v, ok := opts["votefirst"]; ok {
			val, err := toUint64Interface(v)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("keyreg() invalid votefirst: %v", err)))
			}
			params.VoteFirst = val
		}
		if v, ok := opts["votelast"]; ok {
			val, err := toUint64Interface(v)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("keyreg() invalid votelast: %v", err)))
			}
			params.VoteLast = val
		}
		if v, ok := opts["keydilution"]; ok {
			val, err := toUint64Interface(v)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("keyreg() invalid keydilution: %v", err)))
			}
			params.KeyDilution = val
		}
		if v, ok := opts["eligible"].(bool); ok {
			params.IncentiveEligible = v
		}
	}

	prep, err := a.engine.PrepareKeyReg(params)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("keyreg() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, true)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("keyreg() error submitting transaction: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsParticipation returns participation status for an account.
// participation(address) - Returns participation keys and status
func (a *API) jsParticipation(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "participation() requires an address argument")
	addressOrAlias := call.Arguments[0].String()

	result, err := a.engine.GetParticipationStatus(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("participation() error: %v", err)))
	}

	status := "offline"
	if result.IsOnline {
		status = "online"
	}

	return a.runtime.ToValue(map[string]interface{}{
		"address":           result.Address,
		"status":            status,
		"isOnline":          result.IsOnline,
		"voteKey":           result.VoteKey,
		"selectionKey":      result.SelectionKey,
		"stateProofKey":     result.StateProofKey,
		"voteFirstValid":    result.VoteFirstValid,
		"voteLastValid":     result.VoteLastValid,
		"voteKeyDilution":   result.VoteKeyDilution,
		"incentiveEligible": result.IncentiveEligible,
	})
}

// jsIncentiveEligible checks if an account is eligible for incentives.
// incentiveEligible(address) - Returns boolean
func (a *API) jsIncentiveEligible(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "incentiveEligible() requires an address argument")
	addressOrAlias := call.Arguments[0].String()
	address, _, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("incentiveEligible() error resolving address: %v", err)))
	}

	eligible, err := a.engine.GetIncentiveEligibility(address)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("incentiveEligible() error: %v", err)))
	}

	return a.runtime.ToValue(eligible)
}

// jsRekey rekeys an account to a new auth address.
// rekey(from, to, options) - Rekey 'from' to be controlled by 'to'
func (a *API) jsRekey(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "rekey() requires from and to arguments")
	from := call.Arguments[0].String()
	to := call.Arguments[1].String()

	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		opts := call.Arguments[2].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("rekey() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareRekey(engine.RekeyParams{
		From:       fromAddr,
		To:         toAddr,
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error submitting transaction: %v", err)))
	}

	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsUnrekey rekeys an account back to itself.
// unrekey(account, options) - Rekey 'account' back to self-control
func (a *API) jsUnrekey(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "unrekey() requires an account argument")
	account := call.Arguments[0].String()

	var fee uint64
	var useFlatFee bool
	wait := true

	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		opts := call.Arguments[1].Export().(map[string]interface{})
		if f, ok := opts["fee"]; ok {
			var err error
			fee, err = toUint64Interface(f)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("unrekey() invalid fee: %v", err)))
			}
			useFlatFee = true
		}
		if w, ok := opts["wait"].(bool); ok {
			wait = w
		}
	}

	accountAddr, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("unrekey() error resolving account: %v", err)))
	}

	prep, _, err := a.engine.PrepareRekey(engine.RekeyParams{
		From:       accountAddr,
		To:         accountAddr, // Rekey to self
		Fee:        fee,
		UseFlatFee: useFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("unrekey() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(prep, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("unrekey() error submitting transaction: %v", err)))
	}

	filename, err := a.engine.WriteTransactionJSON(result.Transaction, result.TxID)
	if err != nil {
		a.output(fmt.Sprintf("Warning: failed to write transaction JSON: %v", err))
	} else if filename != "" {
		a.output(fmt.Sprintf("  Saved transaction to %s", filename))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsIsRekeyed checks if an account is rekeyed.
// isRekeyed(address) - Returns {rekeyed: bool, authAddr: string}
func (a *API) jsIsRekeyed(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "isRekeyed() requires an address argument")
	addressOrAlias := call.Arguments[0].String()
	address, _, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("isRekeyed() error resolving address: %v", err)))
	}

	rekeyed, authAddr := a.engine.IsRekeyed(address)

	return a.runtime.ToValue(map[string]interface{}{
		"rekeyed":  rekeyed,
		"authAddr": authAddr,
	})
}
