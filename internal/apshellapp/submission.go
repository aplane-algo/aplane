// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignFileRequest captures parsed inputs for the sign command.
type SignFileRequest struct {
	FilePath string
	Wait     bool
}

// SignFile loads, signs, and submits transactions from a file.
func (a *App) SignFile(ctx context.Context, req SignFileRequest) (*SignFileCommandResult, error) {
	txns, err := algo.ParseTransactionFile(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transaction file: %w", err)
	}

	result, err := a.signTransactions(ctx, txns, req.Wait)
	if err != nil {
		return nil, err
	}

	return &SignFileCommandResult{
		FilePath:  req.FilePath,
		TxCount:   len(txns),
		TxIDs:     append([]string(nil), result.TxIDs...),
		Confirmed: result.Confirmed,
		Output:    result.Output,
		Warnings:  append([]Warning(nil), result.Warnings...),
	}, nil
}

// signTransactions signs and submits pre-built transactions.
func (a *App) signTransactions(ctx context.Context, txns []types.Transaction, wait bool) (*GroupSubmitSummary, error) {
	result, err := a.eng.SignAndSubmitTransactionsWithContext(ctx, txns, wait)
	if err != nil {
		return nil, err
	}
	return newGroupSubmitSummary(
		result.TxIDs,
		result.Confirmed,
		result.Output,
		warningsFromTransactionWriteNotices(result.WriteNotices),
	), nil
}

// SubmitPluginTransactions processes plugin transaction intents and submits them via the appropriate signing path.
func (a *App) SubmitPluginTransactions(ctx context.Context, result *jsonrpc.ExecuteResult, lsigArgs map[string][]byte) (*GroupSubmitSummary, error) {
	if !a.eng.IsConnected() {
		return nil, fmt.Errorf("not connected to signer")
	}

	txns, err := engine.ProcessTransactionIntents(result.Transactions)
	if err != nil {
		return nil, err
	}

	localSigners, err := engine.ParseExecuteResultLocalSigners(result)
	if err != nil {
		return nil, err
	}
	localSignerSet := localSignerSetFromEngine(localSigners)

	lsigArgsSlice := perTxnLsigArgs(lsigArgs, len(result.Transactions))
	if localSignerSet != nil {
		submit, err := a.eng.SignAndSubmitWithLocalSignersWithContext(ctx, txns, localSignerSet.engineSigners, lsigArgsSlice)
		if err != nil {
			if submit != nil {
				return newGroupSubmitSummary(submit.TxIDs, !a.eng.GetSimulate(), submit.Output, nil), err
			}
			return nil, err
		}
		return newGroupSubmitSummary(submit.TxIDs, !a.eng.GetSimulate(), submit.Output, nil), nil
	}
	submit, err := a.eng.SignAndSubmitGroupWithContext(ctx, txns, lsigArgsSlice)
	if err != nil {
		if submit != nil {
			return newGroupSubmitSummary(
				submit.TxIDs,
				submit.Confirmed,
				submit.Output,
				warningsFromTransactionWriteNotices(submit.WriteNotices),
			), err
		}
		return nil, err
	}
	return newGroupSubmitSummary(
		submit.TxIDs,
		submit.Confirmed,
		submit.Output,
		warningsFromTransactionWriteNotices(submit.WriteNotices),
	), nil
}

func perTxnLsigArgs(lsigArgs map[string][]byte, count int) []map[string][]byte {
	if len(lsigArgs) == 0 || count == 0 {
		return nil
	}
	perTxn := make([]map[string][]byte, count)
	for i := range perTxn {
		perTxn[i] = lsigArgs
	}
	return perTxn
}
