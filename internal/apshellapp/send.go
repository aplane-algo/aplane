// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signing"
)

// SendRequest captures parsed send-command inputs before semantic resolution.
type SendRequest struct {
	AmountText string
	AssetRef   string
	FromRaw    []string
	ToRaw      []string
	Note       string
	Wait       bool
	Atomic     bool
	Fee        uint64
	UseFlatFee bool
	LsigArgs   map[string][]byte
}

// PrepareSend resolves addresses, amount metadata, and execution mode for a send command.
func (a *App) PrepareSend(_ context.Context, req SendRequest) (*SendPlan, error) {
	resolver := a.eng.NewAddressResolver()

	fromAddresses, err := cmdspec.ResolveAddressList(req.FromRaw, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source addresses: %w", err)
	}
	toAddresses, err := cmdspec.ResolveAddressList(req.ToRaw, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve destination addresses: %w", err)
	}

	isFromSet := len(fromAddresses) > 1
	isToSet := len(toAddresses) > 1
	if isFromSet && isToSet {
		return nil, fmt.Errorf("cannot have multiple senders AND multiple receivers. Use: 1-to-many, many-to-1, or 1-to-1")
	}

	amount, err := cmdspec.ResolveAssetAmount(a.Network(), req.AssetRef, req.AmountText, a.eng.ASAResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve amount for asset %q: %w", req.AssetRef, err)
	}

	mode := SendModeNonAtomic
	if req.Atomic {
		if isFromSet {
			mode = SendModeAtomicFromMultiple
		} else if isToSet {
			mode = SendModeAtomicToMultiple
		}
	}

	return &SendPlan{
		Mode:          mode,
		FromAddresses: fromAddresses,
		ToAddresses:   toAddresses,
		Amount:        amount,
		Note:          req.Note,
		Wait:          req.Wait,
		Fee:           req.Fee,
		UseFlatFee:    req.UseFlatFee,
		LsigArgs:      req.LsigArgs,
	}, nil
}

// ExecuteSend resolves, prepares, and executes a send request.
// This keeps send workflow branching inside apshellapp rather than adapters.
func (a *App) ExecuteSend(ctx context.Context, req SendRequest) (*SendExecutionResult, error) {
	plan, err := a.PrepareSend(ctx, req)
	if err != nil {
		return nil, err
	}

	result := &SendExecutionResult{
		Mode:   plan.Mode,
		Amount: plan.Amount,
		Note:   plan.Note,
		Wait:   plan.Wait,
		From:   append([]string(nil), plan.FromAddresses...),
		To:     append([]string(nil), plan.ToAddresses...),
	}

	switch plan.Mode {
	case SendModeAtomicFromMultiple, SendModeAtomicToMultiple:
		atomicPlan, err := a.prepareAtomicSend(ctx, plan)
		if err != nil {
			return nil, err
		}
		atomicResult, err := a.executeAtomicSend(ctx, atomicPlan)
		if err != nil {
			return nil, err
		}
		result.Atomic = atomicResult
		return result, nil
	case SendModeNonAtomic:
		nonAtomicPlan, err := a.prepareNonAtomicSend(ctx, plan)
		if err != nil {
			return nil, err
		}
		nonAtomicResult, err := a.executeNonAtomicSend(ctx, nonAtomicPlan, plan.Wait)
		if err != nil {
			return nil, err
		}
		nonAtomicResult.FromCount = len(plan.FromAddresses)
		nonAtomicResult.ToCount = len(plan.ToAddresses)
		result.NonAtomic = nonAtomicResult
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported send mode: %s", plan.Mode)
	}
}

// prepareNonAtomicSend prepares each transaction for a non-atomic send flow.
func (a *App) prepareNonAtomicSend(ctx context.Context, plan *SendPlan) (*NonAtomicSendPlan, error) {
	if plan == nil {
		return nil, fmt.Errorf("send plan is nil")
	}
	if plan.Mode != SendModeNonAtomic {
		return nil, fmt.Errorf("send plan mode %q is not non-atomic", plan.Mode)
	}

	iterCount := len(plan.ToAddresses)
	if len(plan.FromAddresses) > iterCount {
		iterCount = len(plan.FromAddresses)
	}

	items := make([]PreparedSendItem, 0, iterCount)
	for idx := 0; idx < iterCount; idx++ {
		fromAddr := plan.FromAddresses[0]
		if len(plan.FromAddresses) > 1 {
			fromAddr = plan.FromAddresses[idx]
		}
		toAddr := plan.ToAddresses[0]
		if len(plan.ToAddresses) > 1 {
			toAddr = plan.ToAddresses[idx]
		}

		item := PreparedSendItem{From: fromAddr, To: toAddr}
		assetID := plan.Amount.Meta.AssetID
		amountUnits := plan.Amount.Raw

		var err error
		if assetID == 0 {
			prep, check, prepErr := a.eng.PreparePayment(ctx, engine.SendPaymentParams{
				From:       fromAddr,
				To:         toAddr,
				Amount:     amountUnits,
				Note:       plan.Note,
				Fee:        plan.Fee,
				UseFlatFee: plan.UseFlatFee,
				LsigArgs:   plan.LsigArgs,
			})
			item.Prep = preparedTxnFromEngine(prep)
			item.BalanceCheck = balanceCheckDetailsFromEngine(check)
			err = prepErr
		} else {
			prep, check, prepErr := a.eng.PrepareASATransfer(ctx, engine.SendASAParams{
				From:       fromAddr,
				To:         toAddr,
				AssetID:    assetID,
				Amount:     amountUnits,
				Note:       plan.Note,
				Fee:        plan.Fee,
				UseFlatFee: plan.UseFlatFee,
				LsigArgs:   plan.LsigArgs,
			})
			item.Prep = preparedTxnFromEngine(prep)
			item.BalanceCheck = balanceCheckDetailsFromEngine(check)
			err = prepErr
		}
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return &NonAtomicSendPlan{
		Amount:    plan.Amount,
		Items:     items,
		FromCount: len(plan.FromAddresses),
		ToCount:   len(plan.ToAddresses),
	}, nil
}

// prepareAtomicSend prepares an atomic send flow after mode/amount resolution.
func (a *App) prepareAtomicSend(ctx context.Context, plan *SendPlan) (*AtomicSendPlan, error) {
	if plan == nil {
		return nil, fmt.Errorf("send plan is nil")
	}
	if plan.Mode != SendModeAtomicToMultiple && plan.Mode != SendModeAtomicFromMultiple {
		return nil, fmt.Errorf("send plan mode %q is not atomic", plan.Mode)
	}

	assetID := plan.Amount.Meta.AssetID
	amountUnits := plan.Amount.Raw
	groupParams := engine.AtomicGroupParams{
		Fee:        plan.Fee,
		UseFlatFee: plan.UseFlatFee,
	}

	result := &AtomicSendPlan{
		Mode:        plan.Mode,
		Amount:      plan.Amount,
		From:        plan.FromAddresses,
		To:          plan.ToAddresses,
		Wait:        plan.Wait,
		GroupParams: groupParams,
	}

	switch plan.Mode {
	case SendModeAtomicToMultiple:
		if assetID == 0 {
			payments := make([]engine.AtomicPaymentParams, len(plan.ToAddresses))
			for i, to := range plan.ToAddresses {
				payments[i] = engine.AtomicPaymentParams{From: plan.FromAddresses[0], To: to, Amount: amountUnits, Note: plan.Note}
			}
			checks, err := a.eng.ValidateAtomicPayments(ctx, payments, plan.Fee)
			if err != nil {
				return nil, err
			}
			prep, err := a.eng.PrepareAtomicPayments(ctx, payments, groupParams)
			if err != nil {
				return nil, err
			}
			result.Checks = balanceCheckDetailsListFromEngine(checks)
			result.Prep = preparedAtomicGroupFromEngine(prep)
			return result, nil
		}

		transfers := make([]engine.AtomicASAParams, len(plan.ToAddresses))
		for i, to := range plan.ToAddresses {
			transfers[i] = engine.AtomicASAParams{From: plan.FromAddresses[0], To: to, AssetID: assetID, Amount: amountUnits, Note: plan.Note}
		}
		checks, err := a.eng.ValidateAtomicASATransfers(ctx, transfers)
		if err != nil {
			return nil, err
		}
		prep, err := a.eng.PrepareAtomicASATransfers(ctx, transfers, groupParams)
		if err != nil {
			return nil, err
		}
		result.Checks = balanceCheckDetailsListFromEngine(checks)
		result.Prep = preparedAtomicGroupFromEngine(prep)
		return result, nil

	case SendModeAtomicFromMultiple:
		if assetID == 0 {
			payments := make([]engine.AtomicPaymentParams, len(plan.FromAddresses))
			for i, from := range plan.FromAddresses {
				payments[i] = engine.AtomicPaymentParams{From: from, To: plan.ToAddresses[0], Amount: amountUnits, Note: plan.Note}
			}
			checks, err := a.eng.ValidateAtomicPayments(ctx, payments, plan.Fee)
			if err != nil {
				return nil, err
			}
			prep, err := a.eng.PrepareAtomicPayments(ctx, payments, groupParams)
			if err != nil {
				return nil, err
			}
			result.Checks = balanceCheckDetailsListFromEngine(checks)
			result.Prep = preparedAtomicGroupFromEngine(prep)
			return result, nil
		}

		transfers := make([]engine.AtomicASAParams, len(plan.FromAddresses))
		for i, from := range plan.FromAddresses {
			transfers[i] = engine.AtomicASAParams{From: from, To: plan.ToAddresses[0], AssetID: assetID, Amount: amountUnits, Note: plan.Note}
		}
		checks, err := a.eng.ValidateAtomicASATransfers(ctx, transfers)
		if err != nil {
			return nil, err
		}
		prep, err := a.eng.PrepareAtomicASATransfers(ctx, transfers, groupParams)
		if err != nil {
			return nil, err
		}
		result.Checks = balanceCheckDetailsListFromEngine(checks)
		result.Prep = preparedAtomicGroupFromEngine(prep)
		return result, nil
	}

	return nil, fmt.Errorf("unsupported atomic send mode: %s", plan.Mode)
}

// executeNonAtomicSend validates and executes a prepared non-atomic send flow.
func (a *App) executeNonAtomicSend(ctx context.Context, plan *NonAtomicSendPlan, wait bool) (*NonAtomicSendResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("non-atomic send plan is nil")
	}

	result := &NonAtomicSendResult{Amount: plan.Amount}
	for _, item := range plan.Items {
		itemResult := SendItemResult{
			From:           item.From,
			To:             item.To,
			SigningKeyType: item.Prep.SigningContext.DisplayKeyType,
		}

		if err := validatePreparedSendItem(item, plan.Amount); err != nil {
			itemResult.Error = err.Error()
			result.LastError = itemResult.Error
			result.FailureCount++
			result.Items = append(result.Items, itemResult)
			continue
		}

		itemResult.Warnings = sendWarnings(item, plan.Amount)
		submit, err := a.eng.SignAndSubmit(ctx, item.Prep.enginePrep, wait)
		if err != nil {
			if submit != nil {
				itemResult.TxID = submit.TxID
				itemResult.Confirmed = submit.Confirmed
				itemResult.Output = submit.Output
				itemResult.Warnings = append(itemResult.Warnings, warningsFromTransactionWriteNotices(submit.WriteNotices)...)
			}
			itemResult.Error = fmt.Sprintf("transaction failed: %v", err)
			result.LastError = itemResult.Error
			result.FailureCount++
		} else {
			itemResult.TxID = submit.TxID
			itemResult.Confirmed = submit.Confirmed
			itemResult.Output = submit.Output
			itemResult.Warnings = append(itemResult.Warnings, warningsFromTransactionWriteNotices(submit.WriteNotices)...)
			result.SuccessCount++
		}
		result.Items = append(result.Items, itemResult)
	}

	return result, nil
}

// executeAtomicSend validates and executes a prepared atomic send flow.
func (a *App) executeAtomicSend(ctx context.Context, plan *AtomicSendPlan) (*AtomicSendResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("atomic send plan is nil")
	}

	notes, err := atomicValidationNotes(plan)
	if err != nil {
		return nil, err
	}

	submit, err := a.eng.SignAndSubmitAtomic(ctx, plan.Prep.enginePrep, plan.Wait)
	if err != nil {
		return nil, fmt.Errorf("atomic transaction group failed: %w", err)
	}

	return &AtomicSendResult{
		Mode:            plan.Mode,
		Amount:          plan.Amount,
		From:            plan.From,
		To:              plan.To,
		ValidationNotes: notes,
		TxIDs:           submit.TxIDs,
		Confirmed:       submit.Confirmed,
		Output:          submit.Output,
		Warnings:        warningsFromTransactionWriteNotices(submit.WriteNotices),
	}, nil
}

func validatePreparedSendItem(item PreparedSendItem, amount asa.Amount) error {
	assetID := amount.Meta.AssetID
	assetName := asa.DisplayRef(amount.Meta)
	if !item.BalanceCheck.SufficientFunds {
		return fmt.Errorf("insufficient balance: have %.6f, need %.6f %s",
			item.BalanceCheck.SenderBalance, item.BalanceCheck.RequiredAmount, assetName)
	}
	if assetID != 0 && !item.BalanceCheck.ReceiverOptedIn {
		return fmt.Errorf("receiver %s is not opted into ASA %d (%s)",
			item.To, assetID, assetName)
	}
	if assetID == 0 && item.BalanceCheck.NewAccount && amount.Raw < 100000 {
		return fmt.Errorf("recipient is a new account and needs at least 0.1 ALGO minimum balance")
	}
	return nil
}

func sendWarnings(item PreparedSendItem, amount asa.Amount) []Warning {
	if amount.Meta.AssetID != 0 {
		return nil
	}
	if item.BalanceCheck.BelowMinBalance {
		minBalanceAlgo := float64(item.BalanceCheck.MinBalance) / 1000000.0
		remainingAlgo := float64(item.BalanceCheck.RemainingBalance) / 1000000.0
		return []Warning{{
			Code:    "below_min_balance",
			Message: fmt.Sprintf("After this transaction, balance will be %.6f ALGO, below minimum balance of %.6f ALGO", remainingAlgo, minBalanceAlgo),
		}}
	}
	return nil
}

func atomicValidationNotes(plan *AtomicSendPlan) ([]string, error) {
	amount := plan.Amount
	assetName := asa.DisplayRef(amount.Meta)
	switch plan.Mode {
	case SendModeAtomicToMultiple:
		if amount.Meta.AssetID == 0 {
			// Validate the whole group's total against the balance, not just one
			// payment: Checks[0].SufficientFunds only covers a single amount+fee,
			// so a sender with enough for one leg but not all N would otherwise
			// pass pre-flight and fail on-chain. Unlike the ASA branch below
			// (whose fees are paid in ALGO, separate from the swept asset), the
			// ALGO total must include every leg's fee, since they all draw from
			// this same balance.
			totalAmount, ok := checkedSendTotal(amount.Raw, len(plan.To))
			if !ok {
				return nil, fmt.Errorf("total send amount overflows uint64 for %d payments", len(plan.To))
			}
			perTxnFee := uint64(signing.DefaultMinFee)
			if plan.GroupParams.UseFlatFee {
				perTxnFee = plan.GroupParams.Fee
			}
			totalFees, ok := checkedSendTotal(perTxnFee, len(plan.To))
			if !ok {
				return nil, fmt.Errorf("total fee overflows uint64 for %d payments", len(plan.To))
			}
			totalRaw := totalAmount + totalFees
			if totalRaw < totalAmount {
				return nil, fmt.Errorf("total amount plus fees overflows uint64 for %d payments", len(plan.To))
			}
			totalNeeded := float64(totalRaw) / 1000000.0
			if plan.Checks[0].SenderBalance < totalNeeded {
				return nil, fmt.Errorf("insufficient balance: have %.6f ALGO, need %.6f ALGO for %d payments",
					plan.Checks[0].SenderBalance, totalNeeded, len(plan.To))
			}
			for _, check := range plan.Checks {
				if check.NewAccount && amount.Raw < 100000 {
					return nil, fmt.Errorf("recipient is a new account and needs at least 0.1 ALGO")
				}
			}
			return []string{fmt.Sprintf("Sender has %.6f ALGO %s", plan.Checks[0].SenderBalance, checkMark())}, nil
		}
		totalRaw, ok := checkedSendTotal(amount.Raw, len(plan.To))
		if !ok {
			return nil, fmt.Errorf("total send amount overflows uint64 for %d transfers", len(plan.To))
		}
		totalNeeded := float64(totalRaw)
		if plan.Checks[0].SenderBalance < totalNeeded {
			return nil, fmt.Errorf("insufficient balance: have %.0f %s, need %.0f %s",
				plan.Checks[0].SenderBalance, assetName, totalNeeded, assetName)
		}
		for _, check := range plan.Checks {
			if !check.ReceiverOptedIn {
				return nil, fmt.Errorf("receiver is not opted into ASA %d (%s)", amount.Meta.AssetID, assetName)
			}
		}
		return []string{
			fmt.Sprintf("Sender has %.0f %s %s", plan.Checks[0].SenderBalance, assetName, checkMark()),
			fmt.Sprintf("All receivers are opted into %s %s", assetName, checkMark()),
		}, nil
	case SendModeAtomicFromMultiple:
		notes := make([]string, 0, len(plan.Checks)+1)
		if amount.Meta.AssetID == 0 {
			for _, check := range plan.Checks {
				if !check.SufficientFunds {
					return nil, fmt.Errorf("one or more senders have insufficient balance")
				}
				notes = append(notes, fmt.Sprintf("Sender has %.6f ALGO %s", check.SenderBalance, checkMark()))
			}
			if plan.Checks[0].NewAccount && amount.Raw < 100000 {
				return nil, fmt.Errorf("receiver is a new account and needs at least 0.1 ALGO")
			}
			return notes, nil
		}
		for _, check := range plan.Checks {
			if !check.SufficientFunds {
				return nil, fmt.Errorf("one or more senders have insufficient %s", assetName)
			}
			notes = append(notes, fmt.Sprintf("Sender has %.0f %s %s", check.SenderBalance, assetName, checkMark()))
		}
		if !plan.Checks[0].ReceiverOptedIn {
			return nil, fmt.Errorf("receiver is not opted into ASA %d (%s)", amount.Meta.AssetID, assetName)
		}
		notes = append(notes, fmt.Sprintf("Receiver is opted into %s %s", assetName, checkMark()))
		return notes, nil
	default:
		return nil, fmt.Errorf("unsupported atomic send mode: %s", plan.Mode)
	}
}

func checkedSendTotal(amount uint64, count int) (uint64, bool) {
	const maxUint64 = ^uint64(0)

	if count < 0 {
		return 0, false
	}
	if count == 0 || amount == 0 {
		return 0, true
	}
	n := uint64(count)
	if amount > maxUint64/n {
		return 0, false
	}
	return amount * n, true
}

func checkMark() string {
	return "✓"
}
