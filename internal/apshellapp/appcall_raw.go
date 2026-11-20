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

// AppTxnOptions are the program, note and fee options app call and app
// deploy both take.
type AppTxnOptions struct {
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	Note             string
	Fee              uint64
	UseFlatFee       bool
}

// AppCallOptions are the options both forms of app call take.
type AppCallOptions struct {
	PayAmount    uint64
	Accounts     []string
	ForeignApps  []uint64
	AssetRefs    []cmdspec.AssetRef
	Boxes        []types.AppBoxReference
	OnCompletion types.OnCompletion
	Wait         bool
	LsigArgs     cmdspec.LsigArgs
	AppTxnOptions
}

// AppCallRawRequest captures the parsed raw app call request.
type AppCallRawRequest struct {
	AppID   uint64
	From    string
	AppArgs [][]byte
	AppCallOptions
}

// AppCallRaw executes the semantic part of a raw app call.
func (a *App) AppCallRaw(ctx context.Context, req AppCallRawRequest) (*AppCallRawResult, error) {
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
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)

	refs := countReferences(prepResult.Transaction)
	result := &AppCallRawResult{
		FromAddress:    fromAddr,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		AppArgsCount:   len(req.AppArgs),
		AccountsCount:  refs.accounts,
		AppsCount:      refs.apps,
		AssetsCount:    refs.assets,
		BoxesCount:     refs.boxes,
		Note:           req.Note,
		PayAmount:      req.PayAmount,
		Structured: appresult.AppCall{
			AppID: req.AppID,
			Mode:  "raw",
		},
	}
	decorateAppCallRawResult(result)

	result.Output, result.Warnings, err = a.submitAppCall(ctx, "raw app call", fromAddr, req.AppID, prep, req.AppCallOptions, lsigArgs, &result.Structured)
	if err != nil {
		return nil, err
	}
	appendAppCallRawConfirmedLines(result)
	return result, nil
}

// submitAppCall signs and submits a prepared app call from fromAddr, and
// records the submission in structured. With a companion payment, the
// payment to the app's address is prepared and goes first, in one group with
// the call. label names the call in a failure.
func (a *App) submitAppCall(ctx context.Context, label, fromAddr string, appID uint64, call *PreparedTxn, opts AppCallOptions, lsigArgs engine.LsigArgs, structured *appresult.AppCall) (string, []Warning, error) {
	if opts.PayAmount == 0 {
		submit, err := a.eng.SignAndSubmit(ctx, call.enginePrep, lsigArgs, opts.Wait)
		if err != nil {
			return "", nil, fmt.Errorf("%s failed: %w", label, err)
		}
		structured.TxID = submit.TxID
		structured.TxIDs = []string{submit.TxID}
		structured.Confirmed = submit.Confirmed
		return submit.Output, submissionWarnings(submit.WriteNotices, submit.AuthRefreshWarning), nil
	}

	paymentPrepResult, _, err := a.eng.PreparePayment(ctx, engine.SendPaymentParams{
		From:       fromAddr,
		To:         crypto.GetApplicationAddress(appID).String(),
		Amount:     opts.PayAmount,
		Fee:        opts.Fee,
		UseFlatFee: opts.UseFlatFee,
	})
	if err != nil {
		return "", nil, err
	}
	group, err := prepareTxnGroup(preparedTxnFromEngine(paymentPrepResult), call)
	if err != nil {
		return "", nil, err
	}
	submit, err := a.eng.ExecutePreparedGroup(ctx, group.engineGroup, lsigArgs, opts.Wait)
	if err != nil {
		return "", nil, fmt.Errorf("grouped %s failed: %w", label, err)
	}
	structured.Grouped = true
	structured.TxIDs = submit.TxIDs
	structured.Confirmed = submit.Confirmed
	return submit.Output, submissionWarnings(submit.WriteNotices, submit.AuthRefreshWarning), nil
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

// referenceCounts is how many of each kind of reference an app call carries.
type referenceCounts struct {
	accounts, apps, assets, boxes int
}

// countReferences reads the counts from the built transaction, so the
// summary matches what is signed: the listed references and any the engine
// added, such as an app a box needs.
func countReferences(txn types.Transaction) referenceCounts {
	return referenceCounts{
		accounts: len(txn.Accounts),
		apps:     len(txn.ForeignApps),
		assets:   len(txn.ForeignAssets),
		boxes:    len(txn.BoxReferences),
	}
}
