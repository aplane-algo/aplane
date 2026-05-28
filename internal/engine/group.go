// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

// PreparedGroup is the canonical engine-owned representation of a grouped
// execution plan prior to submission.
type PreparedGroup struct {
	Entries []PreparedGroupEntry
}

// PreparedGroupEntry preserves the prepared transaction together with the
// signing metadata derived during transaction preparation.
type PreparedGroupEntry struct {
	Transaction    types.Transaction
	SigningContext *SigningContext
	LsigArgs       map[string][]byte
	AppCallInfo    *signerapi.AppCallInfo
}

// PreparedGroupSubmitResult contains the result of executing a prepared group.
type PreparedGroupSubmitResult struct {
	TxIDs        []string
	Transactions []types.Transaction
	Confirmed    bool
	Output       string
	WriteNotices []TransactionWriteNotice
}

type paymentAppGroupPreparer interface {
	PreparePaymentWithContext(context.Context, SendPaymentParams) (*TransactionPrepResult, *BalanceCheckResult, error)
	PrepareAppCallRawWithContext(context.Context, RawAppCallParams) (*TransactionPrepResult, error)
}

type paymentMethodGroupPreparer interface {
	PreparePaymentWithContext(context.Context, SendPaymentParams) (*TransactionPrepResult, *BalanceCheckResult, error)
	PrepareAppCallMethodWithContext(context.Context, MethodAppCallParams) (*PreparedMethodAppCall, error)
}

// PrepareGroup assembles prepared transactions into a canonical grouped plan.
func PrepareGroup(preps ...*TransactionPrepResult) (*PreparedGroup, error) {
	if len(preps) == 0 {
		return nil, fmt.Errorf("no prepared transactions provided")
	}
	if len(preps) < 2 {
		return nil, fmt.Errorf("prepared group requires at least 2 transactions")
	}

	entries := make([]PreparedGroupEntry, len(preps))
	for i, prep := range preps {
		if prep == nil {
			return nil, fmt.Errorf("prepared transaction %d is nil", i+1)
		}
		if prep.SigningContext == nil {
			return nil, fmt.Errorf("prepared transaction %d is missing signing context", i+1)
		}
		entries[i] = PreparedGroupEntry{
			Transaction:    prep.Transaction,
			SigningContext: prep.SigningContext,
			LsigArgs:       prep.LsigArgs,
			AppCallInfo:    prep.AppCallInfo,
		}
	}

	return &PreparedGroup{Entries: entries}, nil
}

// Transactions returns the group's transactions in order.
func (g *PreparedGroup) Transactions() []types.Transaction {
	if g == nil {
		return nil
	}
	txns := make([]types.Transaction, len(g.Entries))
	for i, entry := range g.Entries {
		txns[i] = entry.Transaction
	}
	return txns
}

// LsigArgsMap returns per-entry LogicSig args in transaction order.
func (g *PreparedGroup) LsigArgsMap() []map[string][]byte {
	if g == nil {
		return nil
	}
	lsigArgs := make([]map[string][]byte, len(g.Entries))
	for i, entry := range g.Entries {
		if len(entry.LsigArgs) == 0 {
			continue
		}
		lsigArgs[i] = entry.LsigArgs
	}
	return lsigArgs
}

// AppCallInfoMap returns per-entry app-call metadata in transaction order.
func (g *PreparedGroup) AppCallInfoMap() []*signerapi.AppCallInfo {
	if g == nil {
		return nil
	}
	info := make([]*signerapi.AppCallInfo, len(g.Entries))
	for i, entry := range g.Entries {
		info[i] = entry.AppCallInfo
	}
	return info
}

// ExecutePreparedGroupWithContext signs and submits a prepared group using the
// existing grouped signing/submission flow and the caller's context.
func (e *Engine) ExecutePreparedGroupWithContext(ctx context.Context, group *PreparedGroup, wait bool) (*PreparedGroupSubmitResult, error) {
	if group == nil {
		return nil, fmt.Errorf("prepared group is nil")
	}
	if len(group.Entries) == 0 {
		return nil, fmt.Errorf("prepared group contains no entries")
	}

	txns := group.Transactions()
	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptionsWithContext(ctx, wait, &writeNotices, &output)
	opts.LsigArgsMap = group.LsigArgsMap()
	opts.AppCallInfo = group.AppCallInfoMap()
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, opts)
	result := &PreparedGroupSubmitResult{
		TxIDs:        txIDs,
		Transactions: originalSubmittedTransactions(txns, submittedTxns),
		Confirmed:    wait && !e.Simulate && len(txIDs) > 0 && err == nil,
		Output:       output.String(),
		WriteNotices: writeNotices,
	}
	if err != nil {
		return result, fmt.Errorf("failed to sign and submit prepared group: %w", errorWithSubmissionOutput(err, output.String()))
	}

	return result, nil
}

// PreparePaymentAppGroupWithContext prepares a payment and raw app call as one grouped plan.
func PreparePaymentAppGroupWithContext(ctx context.Context, prepper paymentAppGroupPreparer, payment SendPaymentParams, app RawAppCallParams) (*PreparedGroup, error) {
	paymentPrep, _, err := prepper.PreparePaymentWithContext(ctx, payment)
	if err != nil {
		return nil, err
	}

	appPrep, err := prepper.PrepareAppCallRawWithContext(ctx, app)
	if err != nil {
		return nil, err
	}

	return PrepareGroup(paymentPrep, appPrep)
}

// PreparePaymentMethodGroupWithContext prepares a payment and ABI-backed app call as one grouped plan.
func PreparePaymentMethodGroupWithContext(ctx context.Context, prepper paymentMethodGroupPreparer, payment SendPaymentParams, app MethodAppCallParams) (*PreparedGroup, error) {
	paymentPrep, _, err := prepper.PreparePaymentWithContext(ctx, payment)
	if err != nil {
		return nil, err
	}

	appPrep, err := prepper.PrepareAppCallMethodWithContext(ctx, app)
	if err != nil {
		return nil, err
	}

	return PrepareGroup(paymentPrep, appPrep.Prep)
}
