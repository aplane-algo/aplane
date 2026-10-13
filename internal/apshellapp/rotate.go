// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
)

// RotateRequest asks for a rotate-only spend: a 0-ALGO payment from a
// rotating account to itself, which moves the account to its next stage.
type RotateRequest struct {
	Account string
	Wait    bool
}

// RotateCommandResult reports a rotate-only spend.
type RotateCommandResult struct {
	Account            string
	PreviousAuthorizer string
	Authorizer         string
	TxID               string
	Confirmed          bool
	Output             string
	Warnings           []Warning
}

// RotatingAccountStatus is one rotating account's chain and signer view.
// Alerts need action; Notes are information, such as a release still in
// flight or a stage the signer is still looking for.
type RotatingAccountStatus struct {
	Account    string
	Authorizer string
	Alerts     []string
	Notes      []string
}

// RotateStatusResult reports rotating accounts.
type RotateStatusResult struct {
	Accounts []RotatingAccountStatus
}

// Rotate sends a rotate-only spend. It is the remedy for a stage whose keys
// were revealed by a transaction that will never confirm, and the way to
// move an account on without spending anything.
func (a *App) Rotate(ctx context.Context, req RotateRequest) (*RotateCommandResult, error) {
	address, err := cmdspec.ResolveSingleAddress(req.Account, a.eng.NewAddressResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve account %q: %w", req.Account, err)
	}
	if !a.eng.IsRotatingAccount(address) {
		return nil, fmt.Errorf("%s is not a rotating account", address)
	}
	previous, err := a.eng.RefreshAuthAddressWithContext(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("read current authorizer: %w", err)
	}
	prepResult, _, err := a.eng.PreparePayment(ctx, engine.SendPaymentParams{From: address, To: address})
	if err != nil {
		return nil, err
	}
	submit, err := a.eng.SignAndSubmit(ctx, preparedTxnFromEngine(prepResult).enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("rotate failed: %w", err)
	}
	result := &RotateCommandResult{
		Account:            address,
		PreviousAuthorizer: authorizerOrSelf(previous, address),
		TxID:               submit.TxID,
		Confirmed:          submit.Confirmed,
		Output:             submit.Output,
		Warnings:           warningsFromTransactionWriteNotices(submit.WriteNotices),
	}
	if submit.Confirmed {
		current, err := a.eng.RefreshAuthAddressWithContext(ctx, address)
		if err == nil {
			result.Authorizer = authorizerOrSelf(current, address)
		}
	}
	return result, nil
}

// RotateStatus reports each rotating account's on-chain authorizer and the
// signer's alerts and notes that name it. An empty account reports every
// signable rotating account.
func (a *App) RotateStatus(ctx context.Context, account string) (*RotateStatusResult, error) {
	var accounts []string
	if account == "" {
		accounts = a.eng.RotatingAccounts()
	} else {
		address, err := cmdspec.ResolveSingleAddress(account, a.eng.NewAddressResolver())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve account %q: %w", account, err)
		}
		if !a.eng.IsRotatingAccount(address) {
			return nil, fmt.Errorf("%s is not a rotating account", address)
		}
		accounts = []string{address}
	}
	warnings, notes, err := a.eng.SignerStatusLines(ctx)
	if err != nil {
		return nil, fmt.Errorf("read signer status: %w", err)
	}
	result := &RotateStatusResult{}
	for _, address := range accounts {
		authorizer, err := a.eng.RefreshAuthAddressWithContext(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("read authorizer of %s: %w", address, err)
		}
		status := RotatingAccountStatus{Account: address, Authorizer: authorizerOrSelf(authorizer, address)}
		for _, warning := range warnings {
			if strings.Contains(warning, address) {
				status.Alerts = append(status.Alerts, warning)
			}
		}
		for _, note := range notes {
			if strings.Contains(note, address) {
				status.Notes = append(status.Notes, note)
			}
		}
		result.Accounts = append(result.Accounts, status)
	}
	return result, nil
}

func authorizerOrSelf(authorizer, address string) string {
	if authorizer == "" {
		return address
	}
	return authorizer
}
