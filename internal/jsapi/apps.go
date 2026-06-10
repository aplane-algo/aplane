// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

// JavaScript API functions for Algorand application interaction:
// - App state reads (global, local, box, boxes)
// - Raw app calls
// - ABI-backed app calls

import (
	"fmt"
	"strconv"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/appinput"
	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/engine"
)

type appCallOptions struct {
	txnOptions
	PayAmount     uint64
	Accounts      []string
	ForeignApps   []uint64
	ForeignBoxes  []types.AppBoxReference
	ForeignAssets []uint64
	OnCompletion  types.OnCompletion
}

type appDeployOptions struct {
	txnOptions
	ApprovalCompiled bool
	ClearCompiled    bool
	GlobalUint       uint64
	GlobalBytes      uint64
	LocalUint        uint64
	LocalBytes       uint64
	ExtraPages       uint32
}

func (a *API) jsAppDeploy(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 3, "appDeploy() requires from, approvalPath, and clearPath arguments")

	from := call.Arguments[0].String()
	approvalPath := call.Arguments[1].String()
	clearPath := call.Arguments[2].String()

	opts := a.parseAppDeployOptions(call, 3, "appDeploy()")
	fromAddr, _, err := a.resolveAppAccounts(from, nil, "appDeploy()")
	if err != nil {
		panic(a.runtime.ToValue(err.Error()))
	}

	prep, err := a.engine.PrepareAppDeploy(a.Context(), engine.AppDeployParams{
		From: fromAddr,
		Approval: engine.AppProgramSource{
			Path:     approvalPath,
			Compiled: opts.ApprovalCompiled,
		},
		Clear: engine.AppProgramSource{
			Path:     clearPath,
			Compiled: opts.ClearCompiled,
		},
		GlobalUint:   opts.GlobalUint,
		GlobalBytes:  opts.GlobalBytes,
		LocalUint:    opts.LocalUint,
		LocalBytes:   opts.LocalBytes,
		ExtraPages:   opts.ExtraPages,
		Note:         opts.Note,
		Fee:          opts.Fee,
		UseFlatFee:   opts.UseFlatFee,
		OnCompletion: types.NoOpOC,
	})
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appDeploy() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appDeploy() error submitting transaction: %v", err)))
	}

	out := map[string]interface{}{
		"tx_id":     result.TxID,
		"confirmed": result.Confirmed,
	}
	if opts.Wait && result.Confirmed {
		created, err := a.engine.LookupCreatedApplication(a.Context(), result.TxID)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appDeploy() error resolving created app: %v", err)))
		}
		out["app_id"] = created.AppID
		out["app_address"] = created.AppAddress
	}

	return a.toJSObject(out)
}

func (a *API) jsAppGlobal(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "appGlobal() requires an appId argument")
	appID := toUint64(a.runtime, call.Arguments[0])

	result, err := a.engine.ReadAppGlobalState(a.Context(), appID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appGlobal() error: %v", err)))
	}

	return a.toJSObject(result)
}

func (a *API) jsAppInfo(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "appInfo() requires an appId argument")
	appID := toUint64(a.runtime, call.Arguments[0])

	result, err := a.engine.ReadAppInfo(a.Context(), appID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appInfo() error: %v", err)))
	}

	return a.toJSObject(result)
}

func (a *API) jsAppLocal(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "appLocal() requires appId and account arguments")
	appID := toUint64(a.runtime, call.Arguments[0])
	account := call.Arguments[1].String()

	address, _, err := a.engine.ResolveAddress(account)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appLocal() error resolving account: %v", err)))
	}

	result, err := a.engine.ReadAppLocalState(a.Context(), address, appID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appLocal() error: %v", err)))
	}

	return a.toJSObject(result)
}

func (a *API) jsAppBox(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 2, "appBox() requires appId and box name arguments")
	appID := toUint64(a.runtime, call.Arguments[0])

	name, err := parseJSByteString(call.Arguments[1].Export())
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appBox() invalid box name: %v", err)))
	}

	result, err := a.engine.ReadAppBox(a.Context(), appID, name)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appBox() error: %v", err)))
	}

	return a.toJSObject(result)
}

func (a *API) jsAppBoxes(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 1, "appBoxes() requires an appId argument")
	appID := toUint64(a.runtime, call.Arguments[0])

	result, err := a.engine.ListAppBoxes(a.Context(), appID)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appBoxes() error: %v", err)))
	}

	return a.toJSObject(result)
}

func (a *API) jsAppCallRaw(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 3, "appCallRaw() requires appId, from, and appArgs arguments")

	appID := toUint64(a.runtime, call.Arguments[0])
	from := call.Arguments[1].String()
	appArgs, err := requiredJSArray(call.Arguments[2], "appCallRaw() appArgs")
	if err != nil {
		panic(a.runtime.ToValue(err.Error()))
	}

	opts := a.parseAppCallOptions(call, 3, "appCallRaw()", appID)
	fromAddr, accounts, err := a.resolveAppAccounts(from, opts.Accounts, "appCallRaw()")
	if err != nil {
		panic(a.runtime.ToValue(err.Error()))
	}

	encodedArgs := make([][]byte, len(appArgs))
	for i, raw := range appArgs {
		value, err := parseJSByteString(raw)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() arg %d: %v", i+1, err)))
		}
		encodedArgs[i] = value
	}

	rawParams := engine.RawAppCallParams{
		AppID:         appID,
		From:          fromAddr,
		AppArgs:       encodedArgs,
		Accounts:      accounts,
		ForeignApps:   opts.ForeignApps,
		ForeignAssets: opts.ForeignAssets,
		Boxes:         opts.ForeignBoxes,
		OnCompletion:  opts.OnCompletion,
		Note:          opts.Note,
		Fee:           opts.Fee,
		UseFlatFee:    opts.UseFlatFee,
	}

	if opts.PayAmount > 0 {
		group, err := engine.PreparePaymentAppGroupWithContext(a.Context(), a.engine, engine.SendPaymentParams{
			From:       fromAddr,
			To:         crypto.GetApplicationAddress(appID).String(),
			Amount:     opts.PayAmount,
			Fee:        opts.Fee,
			UseFlatFee: opts.UseFlatFee,
		}, rawParams)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() error preparing grouped call: %v", err)))
		}

		result, err := a.engine.ExecutePreparedGroup(a.Context(), group, opts.Wait)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() error submitting grouped call: %v", err)))
		}
		return a.preparedGroupResultValue(result, "")
	}

	prep, err := a.engine.PrepareAppCallRaw(a.Context(), rawParams)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() error submitting transaction: %v", err)))
	}

	return a.submitResultValue(result, "")
}

func requiredJSArray(value goja.Value, label string) ([]interface{}, error) {
	switch raw := value.Export().(type) {
	case []interface{}:
		return raw, nil
	case []string:
		result := make([]interface{}, len(raw))
		for i, item := range raw {
			result[i] = item
		}
		return result, nil
	default:
		return nil, fmt.Errorf("%s must be an array", label)
	}
}

func (a *API) jsAppCall(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 5, "appCall() requires appId, method, abiPath, from, and args arguments")

	appID := toUint64(a.runtime, call.Arguments[0])
	method := call.Arguments[1].String()
	abiPath := call.Arguments[2].String()
	from := call.Arguments[3].String()
	rawArgs := toInterfaceArray(call.Arguments[4])
	if abiPath == "" {
		panic(a.runtime.ToValue("appCall() error preparing transaction: ABI path is required"))
	}

	opts := a.parseAppCallOptions(call, 5, "appCall()", appID)
	fromAddr, accounts, err := a.resolveAppAccounts(from, opts.Accounts, "appCall()")
	if err != nil {
		panic(a.runtime.ToValue(err.Error()))
	}

	methodArgs := make([]string, len(rawArgs))
	for i, raw := range rawArgs {
		methodArgs[i] = fmt.Sprint(raw)
	}
	spec, err := appspec.Load(abiPath)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing transaction: %v", err)))
	}
	resolvedMethod, err := spec.ResolveMethod(method)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing transaction: %v", err)))
	}
	methodSignature := resolvedMethod.Signature()

	methodParams := engine.MethodAppCallParams{
		ABIPath: abiPath,
		Method:  method,
		Args:    methodArgs,
		RawAppCallParams: engine.RawAppCallParams{
			AppID:         appID,
			From:          fromAddr,
			Accounts:      accounts,
			ForeignApps:   opts.ForeignApps,
			ForeignAssets: opts.ForeignAssets,
			Boxes:         opts.ForeignBoxes,
			OnCompletion:  opts.OnCompletion,
			Note:          opts.Note,
			Fee:           opts.Fee,
			UseFlatFee:    opts.UseFlatFee,
		},
	}

	if opts.PayAmount > 0 {
		group, err := engine.PreparePaymentMethodGroupWithContext(a.Context(), a.engine, engine.SendPaymentParams{
			From:       fromAddr,
			To:         crypto.GetApplicationAddress(appID).String(),
			Amount:     opts.PayAmount,
			Fee:        opts.Fee,
			UseFlatFee: opts.UseFlatFee,
		}, methodParams)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing grouped call: %v", err)))
		}

		result, err := a.engine.ExecutePreparedGroup(a.Context(), group, opts.Wait)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appCall() error submitting grouped call: %v", err)))
		}
		return a.preparedGroupResultValue(result, methodSignature)
	}

	prepared, err := a.engine.PrepareAppCallMethod(a.Context(), methodParams)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prepared.Prep, opts.Wait)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error submitting transaction: %v", err)))
	}

	return a.submitResultValue(result, prepared.Method.Signature())
}

func (a *API) parseAppCallOptions(call goja.FunctionCall, argIndex int, funcName string, appID uint64) appCallOptions {
	opts := appCallOptions{
		txnOptions:   a.parseTxnOptions(call, argIndex, funcName),
		OnCompletion: types.NoOpOC,
	}
	if len(call.Arguments) <= argIndex || goja.IsUndefined(call.Arguments[argIndex]) || goja.IsNull(call.Arguments[argIndex]) {
		return opts
	}

	m, ok := call.Arguments[argIndex].Export().(map[string]interface{})
	if !ok {
		panic(a.runtime.ToValue(fmt.Sprintf("%s options must be an object", funcName)))
	}

	if p, ok := m["pay"]; ok {
		var err error
		opts.PayAmount, err = toUint64Interface(p)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid pay amount: %v", funcName, err)))
		}
	}
	if accounts, ok := m["accounts"]; ok {
		opts.Accounts = toStringArrayValue(accounts)
	}
	if apps, ok := m["apps"]; ok {
		values, err := toUint64SliceValue(apps)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid apps: %v", funcName, err)))
		}
		opts.ForeignApps = values
	}
	if assets, ok := m["assets"]; ok {
		values, err := toUint64SliceValue(assets)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid assets: %v", funcName, err)))
		}
		opts.ForeignAssets = values
	}
	if boxes, ok := m["boxes"]; ok {
		opts.ForeignBoxes = a.parseBoxRefsValue(boxes, appID, funcName)
	}
	if raw, ok := m["onCompletion"].(string); ok {
		onComp, err := parseOnCompletionString(raw)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid onCompletion: %v", funcName, err)))
		}
		opts.OnCompletion = onComp
	}

	return opts
}

func (a *API) parseAppDeployOptions(call goja.FunctionCall, argIndex int, funcName string) appDeployOptions {
	opts := appDeployOptions{
		txnOptions:       a.parseTxnOptions(call, argIndex, funcName),
		ApprovalCompiled: false,
		ClearCompiled:    false,
	}
	m := a.objectArg(call, argIndex, funcName)
	if m == nil {
		return opts
	}

	if v, ok := m["approvalCompiled"]; ok {
		parsed, ok := v.(bool)
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid approvalCompiled: expected boolean", funcName)))
		}
		opts.ApprovalCompiled = parsed
	}
	if v, ok := m["clearCompiled"]; ok {
		parsed, ok := v.(bool)
		if !ok {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid clearCompiled: expected boolean", funcName)))
		}
		opts.ClearCompiled = parsed
	}
	if v, ok := m["globalUint"]; ok {
		parsed, err := toUint64Interface(v)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid globalUint: %v", funcName, err)))
		}
		opts.GlobalUint = parsed
	}
	if v, ok := m["globalBytes"]; ok {
		parsed, err := toUint64Interface(v)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid globalBytes: %v", funcName, err)))
		}
		opts.GlobalBytes = parsed
	}
	if v, ok := m["localUint"]; ok {
		parsed, err := toUint64Interface(v)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid localUint: %v", funcName, err)))
		}
		opts.LocalUint = parsed
	}
	if v, ok := m["localBytes"]; ok {
		parsed, err := toUint64Interface(v)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid localBytes: %v", funcName, err)))
		}
		opts.LocalBytes = parsed
	}
	if v, ok := m["extraPages"]; ok {
		raw, err := toUint64Interface(v)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid extraPages: %v", funcName, err)))
		}
		if raw > uint64(^uint32(0)) {
			panic(a.runtime.ToValue(fmt.Sprintf("%s extraPages exceeds uint32", funcName)))
		}
		opts.ExtraPages = uint32(raw)
	}
	return opts
}

func (a *API) resolveAppAccounts(from string, accounts []string, funcName string) (string, []string, error) {
	fromAddr, _, err := a.engine.ResolveAddress(from)
	if err != nil {
		return "", nil, fmt.Errorf("%s error resolving from address: %v", funcName, err)
	}

	resolvedAccounts := make([]string, 0, len(accounts))
	for i, account := range accounts {
		addr, _, err := a.engine.ResolveAddress(account)
		if err != nil {
			return "", nil, fmt.Errorf("%s error resolving account %d: %v", funcName, i+1, err)
		}
		resolvedAccounts = append(resolvedAccounts, addr)
	}

	return fromAddr, resolvedAccounts, nil
}

func (a *API) parseBoxRefsValue(v interface{}, curAppID uint64, funcName string) []types.AppBoxReference {
	values := toInterfaceSliceValue(v)
	refs := make([]types.AppBoxReference, 0, len(values))
	for i, raw := range values {
		switch box := raw.(type) {
		case string:
			name, err := parseJSByteString(box)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("%s invalid box %d: %v", funcName, i+1, err)))
			}
			if len(name) == 0 {
				panic(a.runtime.ToValue(fmt.Sprintf("%s invalid box %d: box name must be non-empty", funcName, i+1)))
			}
			refs = append(refs, types.AppBoxReference{AppID: curAppID, Name: name})
		case map[string]interface{}:
			appRef := curAppID
			if v, ok := box["appId"]; ok {
				id, err := toUint64Interface(v)
				if err != nil {
					panic(a.runtime.ToValue(fmt.Sprintf("%s invalid box %d appId: %v", funcName, i+1, err)))
				}
				appRef = id
			}
			nameRaw, ok := box["name"]
			if !ok {
				panic(a.runtime.ToValue(fmt.Sprintf("%s box %d missing name", funcName, i+1)))
			}
			name, err := parseJSByteString(nameRaw)
			if err != nil {
				panic(a.runtime.ToValue(fmt.Sprintf("%s invalid box %d name: %v", funcName, i+1, err)))
			}
			if len(name) == 0 {
				panic(a.runtime.ToValue(fmt.Sprintf("%s invalid box %d name: box name must be non-empty", funcName, i+1)))
			}
			refs = append(refs, types.AppBoxReference{AppID: appRef, Name: name})
		default:
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid box %d type %T", funcName, i+1, raw)))
		}
	}
	return refs
}

func (a *API) submitResultValue(result *engine.SubmitResult, method string) goja.Value {
	out := map[string]interface{}{
		"txid":      result.TxID,
		"txids":     []string{result.TxID},
		"confirmed": result.Confirmed,
	}
	if method != "" {
		out["method"] = method
	}
	return a.runtime.ToValue(out)
}

func (a *API) preparedGroupResultValue(result *engine.PreparedGroupSubmitResult, method string) goja.Value {
	out := map[string]interface{}{
		"txids":     result.TxIDs,
		"confirmed": result.Confirmed,
		"grouped":   true,
	}
	if method != "" {
		out["method"] = method
	}
	return a.runtime.ToValue(out)
}

func parseJSByteString(v interface{}) ([]byte, error) {
	switch raw := v.(type) {
	case string:
		return appinput.ParseByteValue(raw)
	case []byte:
		return raw, nil
	case []interface{}:
		out := make([]byte, len(raw))
		for i, item := range raw {
			val, err := toUint64Interface(item)
			if err != nil {
				return nil, fmt.Errorf("invalid byte %d: %v", i, err)
			}
			if val > 255 {
				return nil, fmt.Errorf("invalid byte %d: value %d out of range", i, val)
			}
			out[i] = byte(val)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported byte value type %T", v)
	}
}

func parseOnCompletionString(raw string) (types.OnCompletion, error) {
	return appinput.ParseOnCompletion(raw)
}

func toUint64SliceValue(v interface{}) ([]uint64, error) {
	values := toInterfaceSliceValue(v)
	result := make([]uint64, 0, len(values))
	for i, item := range values {
		switch raw := item.(type) {
		case string:
			parsed, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result = append(result, parsed)
		default:
			parsed, err := toUint64Interface(raw)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result = append(result, parsed)
		}
	}
	return result, nil
}
