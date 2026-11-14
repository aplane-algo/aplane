// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

// JavaScript API functions for Algorand application interaction:
// - App state reads (global, local, box, boxes)
// - Raw app calls
// - ABI-backed app calls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

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

	from := a.stringArg(call, 0)
	approvalPath := a.stringArg(call, 1)
	clearPath := a.stringArg(call, 2)

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

	result, err := a.engine.SignAndSubmit(a.Context(), prep, engine.LsigArgs{}, opts.Wait)
	if err != nil {
		a.throwSubmitError(fmt.Errorf("appDeploy() error submitting transaction: %w", err))
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
	account := a.stringArg(call, 1)

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
	from := a.stringArg(call, 1)
	appArgs, err := jsArray(call.Arguments[2].Export())
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() appArgs: %v", err)))
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

		result, err := a.engine.ExecutePreparedGroup(a.Context(), group, engine.LsigArgs{}, opts.Wait)
		if err != nil {
			a.throwSubmitError(fmt.Errorf("appCallRaw() error submitting grouped call: %w", err))
		}
		return a.preparedGroupResultValue(result, "")
	}

	prep, err := a.engine.PrepareAppCallRaw(a.Context(), rawParams)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCallRaw() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prep, engine.LsigArgs{}, opts.Wait)
	if err != nil {
		a.throwSubmitError(fmt.Errorf("appCallRaw() error submitting transaction: %w", err))
	}

	return a.submitResultValue(result, "")
}

func (a *API) jsAppCall(call goja.FunctionCall) goja.Value {
	a.requireArgs(call, 5, "appCall() requires appId, method, abiPath, from, and args arguments")

	appID := toUint64(a.runtime, call.Arguments[0])
	method := a.stringArg(call, 1)
	abiPath := a.stringArg(call, 2)
	from := a.stringArg(call, 3)
	rawArgs, err := jsArray(call.Arguments[4].Export())
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() args: %v", err)))
	}
	if abiPath == "" {
		panic(a.runtime.ToValue("appCall() error preparing transaction: ABI path is required"))
	}

	opts := a.parseAppCallOptions(call, 5, "appCall()", appID)
	fromAddr, accounts, err := a.resolveAppAccounts(from, opts.Accounts, "appCall()")
	if err != nil {
		panic(a.runtime.ToValue(err.Error()))
	}

	spec, err := appspec.Load(abiPath)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing transaction: %v", err)))
	}
	resolvedMethod, err := spec.ResolveMethod(method)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing transaction: %v", err)))
	}
	methodArgs := make([]string, len(rawArgs))
	for i, raw := range rawArgs {
		// An argument past the method's list has no type; the engine reports
		// the count mismatch.
		typeName := ""
		if i < len(resolvedMethod.Args) {
			typeName = resolvedMethod.Args[i].Type
		}
		methodArgs[i], err = abiArgText(raw, typeName)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("appCall() argument %d: %v", i+1, err)))
		}
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

		result, err := a.engine.ExecutePreparedGroup(a.Context(), group, engine.LsigArgs{}, opts.Wait)
		if err != nil {
			a.throwSubmitError(fmt.Errorf("appCall() error submitting grouped call: %w", err))
		}
		return a.preparedGroupResultValue(result, methodSignature)
	}

	prepared, err := a.engine.PrepareAppCallMethod(a.Context(), methodParams)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("appCall() error preparing transaction: %v", err)))
	}

	result, err := a.engine.SignAndSubmit(a.Context(), prepared.Prep, engine.LsigArgs{}, opts.Wait)
	if err != nil {
		a.throwSubmitError(fmt.Errorf("appCall() error submitting transaction: %w", err))
	}

	return a.submitResultValue(result, prepared.Method.Signature())
}

func (a *API) parseAppCallOptions(call goja.FunctionCall, argIndex int, funcName string, appID uint64) appCallOptions {
	opts := appCallOptions{
		txnOptions:   a.parseTxnOptions(call, argIndex, funcName, "pay", "accounts", "apps", "assets", "boxes", "onCompletion"),
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
		list, err := stringArray(accounts)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid accounts: %v", funcName, err)))
		}
		opts.Accounts = list
	}
	if apps, ok := m["apps"]; ok {
		values, err := toUint64SliceValue(apps)
		if err != nil {
			panic(a.runtime.ToValue(fmt.Sprintf("%s invalid apps: %v", funcName, err)))
		}
		for i, id := range values {
			if id == 0 {
				panic(a.runtime.ToValue(fmt.Sprintf("%s invalid apps: entry %d is 0; a foreign app ID must be non-zero", funcName, i+1)))
			}
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
		opts.ForeignBoxes = a.parseBoxRefsValue(boxes, funcName)
	}
	if raw, ok := a.optionString(m, "onCompletion", funcName); ok {
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
		txnOptions:       a.parseTxnOptions(call, argIndex, funcName, "approvalCompiled", "clearCompiled", "globalUint", "globalBytes", "localUint", "localBytes", "extraPages"),
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

// parseBoxRefsValue reads the `boxes` option. A box given as a name, or as an
// object with no `appId`, belongs to the called app and carries app ID 0,
// which always encodes as index 0, whether or not the called app is also in
// `apps`. An object naming an `appId` asks for that app's position in the list.
func (a *API) parseBoxRefsValue(v interface{}, funcName string) []types.AppBoxReference {
	values, err := jsArray(v)
	if err != nil {
		panic(a.runtime.ToValue(fmt.Sprintf("%s invalid boxes: %v", funcName, err)))
	}
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
			refs = append(refs, types.AppBoxReference{Name: name})
		case map[string]interface{}:
			a.refuseUnknownKeys(box, fmt.Sprintf("%s box %d key", funcName, i+1), "appId", "name")
			appRef := uint64(0)
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

// abiArgText turns one JavaScript ABI argument into the text form the ABI
// argument parser reads, by the argument's own type. Printing the Go value
// would turn a byte array into the text "[1 2 3]".
func abiArgText(raw interface{}, typeName string) (string, error) {
	if appspec.IsByteArrayType(typeName) {
		value, err := parseJSByteString(raw)
		if err != nil {
			return "", err
		}
		return "hex:" + hex.EncodeToString(value), nil
	}
	if typeName == "string" {
		// Sent as written. The text grammar would read a leading "json:" as
		// an instruction, and a number or boolean printed as text is a
		// misplaced argument, not a string.
		text, err := abiStringValue(raw)
		if err != nil {
			return "", err
		}
		encoded, err := json.Marshal(text)
		if err != nil {
			return "", err
		}
		return "json:" + string(encoded), nil
	}
	switch value := raw.(type) {
	case nil:
		return "", fmt.Errorf("null or undefined is not an ABI value")
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case float64:
		if err := checkJSNumber(value); err != nil {
			return "", err
		}
		return strconv.FormatFloat(value, 'f', -1, 64), nil
	case *big.Int:
		return value.String(), nil
	case []byte, []interface{}, map[string]interface{}:
		converted, err := jsonABIValue(value, typeName)
		if err != nil {
			return "", err
		}
		encoded, err := json.Marshal(converted)
		if err != nil {
			return "", err
		}
		return "json:" + string(encoded), nil
	default:
		return "", fmt.Errorf("unsupported ABI value type %T", raw)
	}
}

// abiStringValue accepts only a JavaScript string for an ABI `string`, and
// only one that is intact text, so the bytes sent are the bytes written.
func abiStringValue(raw interface{}) (string, error) {
	text, ok := raw.(string)
	if !ok {
		if raw == nil {
			return "", fmt.Errorf("null or undefined is not an ABI value")
		}
		return "", fmt.Errorf("an ABI string needs a JavaScript string, not %T", raw)
	}
	// A lone surrogate has already become U+FFFD by the time the value is
	// exported from the script, so the replacement character is refused
	// too: it almost always marks text that was damaged on the way here.
	if !utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) {
		return "", fmt.Errorf("the string holds invalid Unicode or the replacement character U+FFFD (a lone surrogate?)")
	}
	return text, nil
}

// maxSafeJSInteger is JavaScript's Number.MAX_SAFE_INTEGER. A whole number
// past it has already been rounded by the time it reaches Go.
const maxSafeJSInteger = 1<<53 - 1

func checkJSNumber(value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("%v is not an ABI value", value)
	}
	if value == math.Trunc(value) && math.Abs(value) > maxSafeJSInteger {
		return fmt.Errorf(
			"%s is past the largest whole number JavaScript holds exactly; pass a BigInt or a decimal string",
			strconv.FormatFloat(value, 'f', -1, 64))
	}
	return nil
}

// jsonABIValue makes a compound JavaScript value safe to marshal as ABI JSON,
// following the ABI type down into arrays and tuples. A byte array is written
// as a list of numbers whatever form it was given in: the ABI library would
// read a string there as base64, and encoding/json would write bytes as
// base64.
func jsonABIValue(raw interface{}, typeName string) (interface{}, error) {
	if appspec.IsByteArrayType(typeName) {
		value, err := parseJSByteString(raw)
		if err != nil {
			return nil, err
		}
		return byteNumbers(value), nil
	}

	if typeName == "string" {
		return abiStringValue(raw)
	}

	switch value := raw.(type) {
	case nil:
		return nil, fmt.Errorf("null or undefined is not an ABI value")
	case string:
		// A decimal string is how a number past 2^53 is passed, nested as
		// well as at the top level. The ABI library reads a JSON string
		// there as an error, so it is written as a number.
		isNumber, err := appspec.CheckNumberText(typeName, value)
		if err != nil {
			return nil, err
		}
		if isNumber {
			return json.Number(value), nil
		}
		return value, nil
	case float64:
		if err := checkJSNumber(value); err != nil {
			return nil, err
		}
		return value, nil
	case *big.Int:
		return json.Number(value.String()), nil
	case []byte:
		return byteNumbers(value), nil
	case []interface{}:
		members, isTuple := appspec.TupleTypes(typeName)
		element, _ := appspec.ElementType(typeName)
		out := make([]interface{}, len(value))
		for i, item := range value {
			itemType := element
			if isTuple {
				itemType = ""
				if i < len(members) {
					itemType = members[i]
				}
			}
			converted, err := jsonABIValue(item, itemType)
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out[i] = converted
		}
		return out, nil
	default:
		return raw, nil
	}
}

func byteNumbers(value []byte) []interface{} {
	out := make([]interface{}, len(value))
	for i, b := range value {
		out[i] = int64(b)
	}
	return out
}

func parseOnCompletionString(raw string) (types.OnCompletion, error) {
	return appinput.ParseOnCompletion(raw)
}

func toUint64SliceValue(v interface{}) ([]uint64, error) {
	values, err := jsArray(v)
	if err != nil {
		return nil, err
	}
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
