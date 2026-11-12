// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// PreparedGroup is the canonical engine-owned representation of a grouped
// execution plan prior to submission. LsigArgs are the LogicSig arguments
// given for the group, one submission: each position gets the ones its
// signing key declares when it is signed.
type PreparedGroup struct {
	Entries  []PreparedGroupEntry
	LsigArgs LsigArgs
}

// PreparedGroupEntry preserves the prepared transaction together with the
// signing metadata derived during transaction preparation.
type PreparedGroupEntry struct {
	Transaction    types.Transaction
	SigningContext *SigningContext
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
	PreparePayment(context.Context, SendPaymentParams) (*TransactionPrepResult, *BalanceCheckResult, error)
	PrepareAppCallRaw(context.Context, RawAppCallParams) (*TransactionPrepResult, error)
}

type paymentMethodGroupPreparer interface {
	PreparePayment(context.Context, SendPaymentParams) (*TransactionPrepResult, *BalanceCheckResult, error)
	PrepareAppCallMethod(context.Context, MethodAppCallParams) (*PreparedMethodAppCall, error)
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
	values := map[string][]byte{}
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
			AppCallInfo:    prep.AppCallInfo,
		}
		// The group is one submission, so it has one set of arguments: each
		// prepared transaction's, which a command gives all of them alike.
		for name, value := range prep.LsigArgs.values {
			if other, seen := values[name]; seen && !bytes.Equal(other, value) {
				return nil, fmt.Errorf("prepared transactions give the LogicSig argument %q different values", name)
			}
			values[name] = value
		}
	}

	group := &PreparedGroup{Entries: entries}
	if len(values) > 0 {
		group.LsigArgs = NewLsigArgs(values)
	}
	return group, nil
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

// ExecutePreparedGroup signs and submits a prepared group using the
// existing grouped signing/submission flow and the caller's context.
func (e *Engine) ExecutePreparedGroup(ctx context.Context, group *PreparedGroup, wait bool) (*PreparedGroupSubmitResult, error) {
	if group == nil {
		return nil, fmt.Errorf("prepared group is nil")
	}
	if len(group.Entries) == 0 {
		return nil, fmt.Errorf("prepared group contains no entries")
	}

	txns := group.Transactions()
	var writeNotices []TransactionWriteNotice
	var output bytes.Buffer
	opts := e.defaultSubmitOptions(ctx, wait, &writeNotices, &output)
	opts.AppCallInfo = group.AppCallInfoMap()
	txIDs, submittedTxns, err := e.signAndSubmitGroup(txns, group.LsigArgs, opts)
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
	paymentPrep, _, err := prepper.PreparePayment(ctx, payment)
	if err != nil {
		return nil, err
	}

	appPrep, err := prepper.PrepareAppCallRaw(ctx, app)
	if err != nil {
		return nil, err
	}

	return PrepareGroup(paymentPrep, appPrep)
}

// PreparePaymentMethodGroupWithContext prepares a payment and ABI-backed app call as one grouped plan.
func PreparePaymentMethodGroupWithContext(ctx context.Context, prepper paymentMethodGroupPreparer, payment SendPaymentParams, app MethodAppCallParams) (*PreparedGroup, error) {
	paymentPrep, _, err := prepper.PreparePayment(ctx, payment)
	if err != nil {
		return nil, err
	}

	appPrep, err := prepper.PrepareAppCallMethod(ctx, app)
	if err != nil {
		return nil, err
	}

	return PrepareGroup(paymentPrep, appPrep.Prep)
}
