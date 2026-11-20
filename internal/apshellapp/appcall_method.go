// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/engine"
)

// AppCallMethodRequest captures the parsed ABI/method app call request.
type AppCallMethodRequest struct {
	AppID     uint64
	Method    string
	ABIPath   string
	ArgValues []string
	From      string
	AppCallOptions
}

// AppCallMethod executes the semantic part of an ABI/method app call.
func (a *App) AppCallMethod(ctx context.Context, req AppCallMethodRequest) (*AppCallMethodResult, error) {
	fromAddr, accounts, foreignAssets, err := a.resolveAppCallInputs(req.From, req.Accounts, req.AssetRefs)
	if err != nil {
		return nil, err
	}
	// A companion payment is from the same account as the call, so a target
	// that names it reaches both transactions.
	lsigArgs, err := a.resolveLsigArgs(req.LsigArgs, []string{fromAddr})
	if err != nil {
		return nil, err
	}

	preparedResult, err := a.eng.PrepareAppCallMethod(ctx, engine.MethodAppCallParams{
		ABIPath: req.ABIPath,
		Method:  req.Method,
		Args:    req.ArgValues,
		RawAppCallParams: engine.RawAppCallParams{
			AppID:         req.AppID,
			From:          fromAddr,
			Accounts:      accounts,
			ForeignApps:   req.ForeignApps,
			ForeignAssets: foreignAssets,
			Boxes:         req.Boxes,
			OnCompletion:  req.OnCompletion,
			Approval: engine.AppProgramSource{
				Path:     req.ApprovalPath,
				Compiled: req.ApprovalCompiled,
			},
			Clear: engine.AppProgramSource{
				Path:     req.ClearPath,
				Compiled: req.ClearCompiled,
			},
			Note:       req.Note,
			Fee:        req.Fee,
			UseFlatFee: req.UseFlatFee,
		},
	})
	if err != nil {
		return nil, err
	}
	prepared := preparedMethodCallFromEngine(preparedResult)

	refs := countReferences(preparedResult.Prep.Transaction)
	result := &AppCallMethodResult{
		FromAddress:    fromAddr,
		SigningKeyType: prepared.Prep.SigningContext.DisplayKeyType,
		Method:         prepared.MethodSignature,
		ArgsCount:      len(req.ArgValues),
		AccountsCount:  refs.accounts,
		AppsCount:      refs.apps,
		AssetsCount:    refs.assets,
		BoxesCount:     refs.boxes,
		Note:           req.Note,
		PayAmount:      req.PayAmount,
		Structured: appresult.AppCall{
			AppID:  req.AppID,
			Method: prepared.MethodSignature,
			Mode:   "abi",
		},
	}
	decorateAppCallMethodResult(result)

	result.Output, result.Warnings, err = a.submitAppCall(ctx, "app call", fromAddr, req.AppID, prepared.Prep, req.AppCallOptions, lsigArgs, &result.Structured)
	if err != nil {
		return nil, err
	}
	appendAppCallMethodConfirmedLines(result)
	return result, nil
}

func decorateAppCallMethodResult(result *AppCallMethodResult) {
	if result == nil {
		return
	}
	if result.PayAmount > 0 {
		result.PreSubmitLines = append(result.PreSubmitLines,
			fmt.Sprintf("Calling app %d method %s from {from} with companion payment of %d microAlgos...", result.Structured.AppID, result.Method, result.PayAmount),
		)
	} else {
		result.PreSubmitLines = append(result.PreSubmitLines,
			fmt.Sprintf("Calling app %d method %s from {from} using %s...", result.Structured.AppID, result.Method, result.SigningKeyType),
		)
	}
	if result.ArgsCount > 0 {
		result.PreSubmitLines = append(result.PreSubmitLines, fmt.Sprintf("Method args: %d", result.ArgsCount))
	}
	if result.AccountsCount > 0 || result.AppsCount > 0 || result.AssetsCount > 0 || result.BoxesCount > 0 {
		result.PreSubmitLines = append(result.PreSubmitLines,
			fmt.Sprintf("References: %d accounts, %d apps, %d assets, %d boxes", result.AccountsCount, result.AppsCount, result.AssetsCount, result.BoxesCount),
		)
	}
	if result.Note != "" {
		result.PreSubmitLines = append(result.PreSubmitLines, fmt.Sprintf("Note: %s", result.Note))
	}
}

// appendAppCallMethodConfirmedLines must run after submission has set
// Structured.Confirmed; decorateAppCallMethodResult runs pre-submit, when
// confirmation state is not yet known.
func appendAppCallMethodConfirmedLines(result *AppCallMethodResult) {
	if result == nil || !result.Structured.Confirmed {
		return
	}
	if result.Structured.Grouped {
		result.ConfirmedLines = append(result.ConfirmedLines, fmt.Sprintf("Confirmed grouped app call %s on app %d", result.Method, result.Structured.AppID))
	} else {
		result.ConfirmedLines = append(result.ConfirmedLines, fmt.Sprintf("Confirmed app call %s on app %d", result.Method, result.Structured.AppID))
	}
}
