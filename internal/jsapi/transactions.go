// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

// JavaScript API functions for transaction operations:
// - ALGO transfers (send, validate, sweep, close)
// - ASA transfers (sendAsset, optIn, optOut)
// - Key registration (keyreg, participation, incentiveEligible)
// - Rekey operations (rekey, unrekey, isRekeyed)
// - External transactions (sign)

import (
	"fmt"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// jsValidate validates signing capability by sending 0 ALGO to self.
func (a *API) jsValidate(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "validate() requires an address or alias argument")
	addressOrAlias := call.Arguments[0].String()

	addr, _, err := a.engine.ResolveAddress(addressOrAlias)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("validate() error resolving address: %v", err)))
	}

	prep, _, err := a.engine.PreparePayment(a.Context(), engine.SendPaymentParams{
		From:   addr,
		To:     addr,
		Amount: 0,
		Note:   "validate",
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("validate() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, true)
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

	opts := a.parseTxnOptions(call, 3, "send()")

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PreparePayment(a.Context(), engine.SendPaymentParams{
		From:       fromAddr,
		To:         toAddr,
		Amount:     amount,
		Note:       opts.Note,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("send() error submitting transaction: %v", err)))
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

	opts := a.parseTxnOptions(call, 2, "sweep()")

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareClose(a.Context(), engine.CloseAccountParams{
		From:       fromAddr,
		CloseTo:    toAddr,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sweep() error submitting transaction: %v", err)))
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

	opts := a.parseTxnOptions(call, 4, "sendAsset()")

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareASATransfer(a.Context(), engine.SendASAParams{
		From:       fromAddr,
		To:         toAddr,
		AssetID:    assetID,
		Amount:     amount,
		Note:       opts.Note,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sendAsset() error submitting transaction: %v", err)))
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

	opts := a.parseTxnOptions(call, 2, "optIn()")

	accountAddr, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optIn() error resolving account: %v", err)))
	}

	prep, err := a.engine.PrepareOptIn(a.Context(), engine.OptInParams{
		Account:    accountAddr,
		AssetID:    assetID,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optIn() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optIn() error submitting transaction: %v", err)))
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

	closeTo, opts := a.parseOptOutArgs(call)

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

	prep, _, err := a.engine.PrepareOptOut(a.Context(), engine.OptOutParams{
		Account:    accountAddr,
		AssetID:    assetID,
		CloseTo:    closeToAddr,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optOut() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("optOut() error submitting transaction: %v", err)))
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
		opts := a.objectArg(call, 2, "keyreg()")
		if opts == nil {
			panic(a.runtime.ToValue("keyreg() online mode requires options with participation keys"))
		}

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

	prep, err := a.engine.PrepareKeyReg(a.Context(), params)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("keyreg() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, true)
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

	result, err := a.engine.GetParticipationStatus(a.Context(), addressOrAlias)
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

	eligible, err := a.engine.GetIncentiveEligibility(a.Context(), address)
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

	opts := a.parseTxnOptions(call, 2, "rekey()")

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareRekey(a.Context(), engine.RekeyParams{
		From:       fromAddr,
		To:         toAddr,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("rekey() error submitting transaction: %v", err)))
	}

	out := map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	}
	if result.AuthRefreshWarning != "" {
		out["authCacheWarning"] = result.AuthRefreshWarning
	}
	return a.runtime.ToValue(out)
}

// jsUnrekey rekeys an account back to itself.
// unrekey(account, options) - Rekey 'account' back to self-control
func (a *API) jsUnrekey(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "unrekey() requires an account argument")
	account := call.Arguments[0].String()

	opts := a.parseTxnOptions(call, 1, "unrekey()")

	accountAddr, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("unrekey() error resolving account: %v", err)))
	}

	prep, _, err := a.engine.PrepareRekey(a.Context(), engine.RekeyParams{
		From:       accountAddr,
		To:         accountAddr, // Rekey to self
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("unrekey() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("unrekey() error submitting transaction: %v", err)))
	}

	out := map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	}
	if result.AuthRefreshWarning != "" {
		out["authCacheWarning"] = result.AuthRefreshWarning
	}
	return a.runtime.ToValue(out)
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

// jsClose closes an account, sending all funds to a destination.
// close(from, to, options) - Close 'from' account, send funds to 'to'
func (a *API) jsClose(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "close() requires from and to arguments")
	from := call.Arguments[0].String()
	to := call.Arguments[1].String()

	opts := a.parseCloseOptions(call)

	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("close() error resolving from address: %v", err)))
	}
	toAddr, _, err := a.engine.ResolveAddress(to)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("close() error resolving to address: %v", err)))
	}

	prep, _, err := a.engine.PrepareClose(a.Context(), engine.CloseAccountParams{
		From:       fromAddr,
		CloseTo:    toAddr,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
		LsigArgs:   opts.LsigArgs,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("close() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("close() error submitting transaction: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txid":      result.TxID,
		"confirmed": result.Confirmed,
	})
}

// jsSign signs and submits transactions loaded from a file.
// sign(filepath) - Sign and submit, wait for confirmation
// sign(filepath, {wait: false}) - Sign and submit without waiting
func (a *API) jsSign(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "sign() requires a filepath argument")
	filepath := call.Arguments[0].String()

	wait := true
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		m := a.objectArg(call, 1, "sign()")
		if m == nil {
			panic(a.runtime.ToValue("sign() options must be an object"))
		}
		if w, ok := m["wait"].(bool); ok {
			wait = w
		}
	}

	txns, err := algo.ParseTransactionFile(filepath)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sign() error parsing file: %v", err)))
	}

	result, err := a.engine.SignAndSubmitTransactions(a.Context(), txns, wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("sign() error: %v", err)))
	}

	return a.runtime.ToValue(map[string]interface{}{
		"txids":     result.TxIDs,
		"confirmed": result.Confirmed,
	})
}

// jsPlan sends transactions to the signer's /plan endpoint for group planning
// without signing or triggering approval. Returns the planned group and mutations.
// plan([{authAddress, txnBytesHex, ...}, ...]) - Plan a transaction group
func (a *API) jsPlan(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "plan() requires an array of sign requests")

	items := call.Arguments[0].Export()
	arr, ok := items.([]interface{})
	if !ok {
		panic(a.runtime.ToValue("plan() argument must be an array of sign request objects"))
	}

	requests := make([]signerapi.SignRequest, len(arr))
	for i, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("plan() request %d: expected object", i+1)))
		}
		if v, ok := m["authAddress"].(string); ok {
			requests[i].AuthAddress = v
		}
		if v, ok := m["txnSender"].(string); ok {
			requests[i].TxnSender = v
		}
		if v, ok := m["txnBytesHex"].(string); ok {
			requests[i].TxnBytesHex = v
		}
		if v, ok := m["signedTxnHex"].(string); ok {
			requests[i].SignedTxnHex = v
		}
		if v, ok := m["lsigResources"]; ok {
			resources, ok := v.(map[string]interface{})
			if !ok {
				panic(a.runtime.ToValue(fmt.Sprintf("plan() request %d: lsigResources must be an object", i+1)))
			}
			read := func(name string) uint64 {
				value, exists := resources[name]
				if !exists {
					panic(a.runtime.ToValue(fmt.Sprintf("plan() request %d: lsigResources.%s is required", i+1, name)))
				}
				parsed, err := toUint64Interface(value)
				if err != nil {
					panic(a.runtime.ToValue(fmt.Sprintf("plan() request %d: invalid lsigResources.%s: %v", i+1, name, err)))
				}
				return parsed
			}
			requests[i].LsigResources = &signerapi.LogicSigResourceUsage{
				ProgramBytes:  read("programBytes"),
				ArgumentBytes: read("argumentBytes"),
				MaxOpcodeCost: read("maxOpcodeCost"),
			}
		}
		if v, ok := m["lsigArgs"].(map[string]interface{}); ok {
			args := make(map[string]string, len(v))
			for k, val := range v {
				s, ok := val.(string)
				if !ok {
					panic(a.runtime.ToValue(fmt.Sprintf("plan() request %d: lsigArgs[%q] must be a hex string", i+1, k)))
				}
				args[k] = s
			}
			requests[i].LsigArgs = args
		}
	}

	resp, err := a.engine.RequestGroupPlanWithContext(a.Context(), requests)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("plan() error: %v", err)))
	}

	result := map[string]interface{}{
		"transactions": resp.Transactions,
	}
	if resp.Mutations != nil {
		result["mutations"] = map[string]interface{}{
			"dummiesAdded":     resp.Mutations.DummiesAdded,
			"groupIDChanged":   resp.Mutations.GroupIDChanged,
			"feesModified":     resp.Mutations.FeesModified,
			"totalFeesDelta":   resp.Mutations.TotalFeesDelta,
			"originalCount":    resp.Mutations.OriginalCount,
			"finalCount":       resp.Mutations.FinalCount,
			"passthroughCount": resp.Mutations.PassthroughCount,
			"foreignCount":     resp.Mutations.ForeignCount,
			"reason":           resp.Mutations.Reason,
		}
	}

	return a.runtime.ToValue(result)
}
