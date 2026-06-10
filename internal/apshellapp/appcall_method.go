// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
)

// AppCallMethodRequest captures the parsed ABI/method app call request.
type AppCallMethodRequest struct {
	AppID            uint64
	Method           string
	ABIPath          string
	ArgValues        []string
	PayAmount        uint64
	From             string
	Accounts         []string
	ForeignApps      []uint64
	AssetRefs        []cmdspec.AssetRef
	Boxes            []types.AppBoxReference
	OnCompletion     types.OnCompletion
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	Note             string
	Wait             bool
	Fee              uint64
	UseFlatFee       bool
	LsigArgs         map[string][]byte
}

// AppCallMethod executes the semantic part of an ABI/method app call.
func (a *App) AppCallMethod(ctx context.Context, req AppCallMethodRequest) (*AppCallMethodResult, error) {
	fromAddr, accounts, foreignAssets, err := a.resolveAppCallInputs(req.From, req.Accounts, req.AssetRefs)
	if err != nil {
		return nil, err
	}

	preparedResult, err := a.eng.PrepareAppCallMethodWithContext(ctx, engine.MethodAppCallParams{
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
			LsigArgs:   req.LsigArgs,
		},
	})
	if err != nil {
		return nil, err
	}
	prepared := preparedMethodCallFromEngine(preparedResult)

	result := &AppCallMethodResult{
		FromAddress:    fromAddr,
		SigningKeyType: prepared.Prep.SigningContext.DisplayKeyType,
		Method:         prepared.MethodSignature,
		ArgsCount:      len(req.ArgValues),
		AccountsCount:  len(accounts),
		AppsCount:      len(req.ForeignApps),
		AssetsCount:    len(foreignAssets),
		BoxesCount:     len(req.Boxes),
		Note:           req.Note,
		PayAmount:      req.PayAmount,
		Structured: appresult.AppCall{
			AppID:  req.AppID,
			Method: prepared.MethodSignature,
			Mode:   "abi",
		},
	}
	decorateAppCallMethodResult(result)

	if req.PayAmount > 0 {
		paymentPrepResult, _, err := a.eng.PreparePaymentWithContext(ctx, engine.SendPaymentParams{
			From:       fromAddr,
			To:         crypto.GetApplicationAddress(req.AppID).String(),
			Amount:     req.PayAmount,
			Fee:        req.Fee,
			UseFlatFee: req.UseFlatFee,
		})
		if err != nil {
			return nil, err
		}
		paymentPrep := preparedTxnFromEngine(paymentPrepResult)

		group, err := prepareTxnGroup(paymentPrep, prepared.Prep)
		if err != nil {
			return nil, err
		}

		submit, err := a.eng.ExecutePreparedGroupWithContext(ctx, group.engineGroup, req.Wait)
		if err != nil {
			return nil, fmt.Errorf("grouped app call failed: %w", err)
		}

		result.Structured.Grouped = true
		result.Structured.TxIDs = submit.TxIDs
		result.Structured.Confirmed = submit.Confirmed
		result.Output = submit.Output
		result.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
		appendAppCallMethodConfirmedLines(result)
		return result, nil
	}

	submit, err := a.eng.SignAndSubmitWithContext(ctx, prepared.Prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("app call failed: %w", err)
	}

	result.Structured.TxID = submit.TxID
	result.Structured.TxIDs = []string{submit.TxID}
	result.Structured.Confirmed = submit.Confirmed
	result.Output = submit.Output
	result.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
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
