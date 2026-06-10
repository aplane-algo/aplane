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

// AppCallRawRequest captures the parsed raw app call request.
type AppCallRawRequest struct {
	AppID            uint64
	From             string
	AppArgs          [][]byte
	PayAmount        uint64
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

// AppCallRaw executes the semantic part of a raw app call.
func (a *App) AppCallRaw(ctx context.Context, req AppCallRawRequest) (*AppCallRawResult, error) {
	fromAddr, accounts, foreignAssets, err := a.resolveAppCallInputs(req.From, req.Accounts, req.AssetRefs)
	if err != nil {
		return nil, err
	}

	prepResult, err := a.eng.PrepareAppCallRaw(ctx, engine.RawAppCallParams{
		AppID:         req.AppID,
		From:          fromAddr,
		AppArgs:       req.AppArgs,
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
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)

	result := &AppCallRawResult{
		FromAddress:    fromAddr,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		AppArgsCount:   len(req.AppArgs),
		AccountsCount:  len(accounts),
		AppsCount:      len(req.ForeignApps),
		AssetsCount:    len(foreignAssets),
		BoxesCount:     len(req.Boxes),
		Note:           req.Note,
		PayAmount:      req.PayAmount,
		Structured: appresult.AppCall{
			AppID: req.AppID,
			Mode:  "raw",
		},
	}
	decorateAppCallRawResult(result)

	if req.PayAmount > 0 {
		paymentPrepResult, _, err := a.eng.PreparePayment(ctx, engine.SendPaymentParams{
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

		group, err := prepareTxnGroup(paymentPrep, prep)
		if err != nil {
			return nil, err
		}

		submit, err := a.eng.ExecutePreparedGroup(ctx, group.engineGroup, req.Wait)
		if err != nil {
			return nil, fmt.Errorf("grouped raw app call failed: %w", err)
		}

		result.Structured.Grouped = true
		result.Structured.TxIDs = submit.TxIDs
		result.Structured.Confirmed = submit.Confirmed
		result.Output = submit.Output
		result.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
		appendAppCallRawConfirmedLines(result)
		return result, nil
	}

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("raw app call failed: %w", err)
	}

	result.Structured.TxID = submit.TxID
	result.Structured.TxIDs = []string{submit.TxID}
	result.Structured.Confirmed = submit.Confirmed
	result.Output = submit.Output
	result.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
	appendAppCallRawConfirmedLines(result)
	return result, nil
}

func decorateAppCallRawResult(result *AppCallRawResult) {
	if result == nil {
		return
	}
	if result.PayAmount > 0 {
		result.PreSubmitLines = append(result.PreSubmitLines,
			fmt.Sprintf("Calling app %d raw from {from} with companion payment of %d microAlgos using %s...", result.Structured.AppID, result.PayAmount, result.SigningKeyType),
		)
	} else {
		result.PreSubmitLines = append(result.PreSubmitLines,
			fmt.Sprintf("Calling app %d from {from} using %s...", result.Structured.AppID, result.SigningKeyType),
		)
	}
	if result.AppArgsCount > 0 {
		result.PreSubmitLines = append(result.PreSubmitLines, fmt.Sprintf("App args: %d", result.AppArgsCount))
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

// appendAppCallRawConfirmedLines must run after submission has set
// Structured.Confirmed; decorateAppCallRawResult runs pre-submit, when
// confirmation state is not yet known.
func appendAppCallRawConfirmedLines(result *AppCallRawResult) {
	if result == nil || !result.Structured.Confirmed {
		return
	}
	if result.Structured.Grouped {
		result.ConfirmedLines = append(result.ConfirmedLines, fmt.Sprintf("Confirmed grouped raw app call on app %d", result.Structured.AppID))
	} else {
		result.ConfirmedLines = append(result.ConfirmedLines, fmt.Sprintf("Confirmed raw app call to app %d", result.Structured.AppID))
	}
}

func (a *App) resolveAppCallInputs(from string, accountRefs []string, assetRefs []cmdspec.AssetRef) (string, []string, []uint64, error) {
	resolver := a.eng.NewAddressResolver()
	fromAddr, err := resolver.ResolveSingle(from)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to resolve sender: %w", err)
	}

	accounts := make([]string, 0, len(accountRefs))
	for _, acct := range accountRefs {
		resolved, err := resolver.ResolveSingle(acct)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to resolve account reference %q: %w", acct, err)
		}
		accounts = append(accounts, resolved)
	}

	foreignAssets, err := cmdspec.ResolveForeignAssetIDs(a.Network(), assetRefs, a.eng.ASAResolver())
	if err != nil {
		return "", nil, nil, err
	}

	return fromAddr, accounts, foreignAssets, nil
}
