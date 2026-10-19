// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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
// flight or a stage the signer is still looking for. Signer is the
// signer's own structured view of the account from its last background
// pass, nil when the signer reported none.
type RotatingAccountStatus struct {
	Account    string
	Authorizer string
	Alerts     []string
	Notes      []string
	Signer     *signerapi.RotatingAccountStatus
}

// RotateStatusResult reports rotating accounts.
type RotateStatusResult struct {
	Accounts []RotatingAccountStatus
}

// RotateRecoverRequest starts or cancels a search for a rotating account's
// live stage on the signer. Stage is an optional hint; Window its probe
// radius; MaxStages the search's derivation budget; TimeoutSeconds its
// derivation-time cap. Zero values take the signer's defaults.
type RotateRecoverRequest struct {
	Account        string
	Cancel         bool
	Stage          *uint64
	Window         uint64
	MaxStages      uint64
	TimeoutSeconds int64
}

// RotateRecoverResult reports the grant started or cancelled.
type RotateRecoverResult struct {
	Account  string
	Action   string
	GrantID  uint64
	Recovery signerapi.RotatingRecoveryStatus
}

// RotateRecover asks the signer to search for a rotating account's live
// stage, or to stop searching. It issues no transaction: the signer
// derives stage addresses into its own cache, and the next transaction
// from the account is prepared without discovery once the stage is cached.
func (a *App) RotateRecover(ctx context.Context, req RotateRecoverRequest) (*RotateRecoverResult, error) {
	address, err := cmdspec.ResolveSingleAddress(req.Account, a.eng.NewAddressResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve account %q: %w", req.Account, err)
	}
	if !a.eng.IsRotatingAccount(address) {
		return nil, fmt.Errorf("%s is not a rotating account", address)
	}
	wire := signerapi.RotatingRecoverRequest{
		Account: address, Action: signerapi.RotatingRecoverActionStart,
		Stage: req.Stage, Window: req.Window, MaxStages: req.MaxStages, TimeoutSeconds: req.TimeoutSeconds,
	}
	if req.Cancel {
		wire = signerapi.RotatingRecoverRequest{Account: address, Action: signerapi.RotatingRecoverActionCancel}
	}
	resp, err := a.eng.RotatingRecover(ctx, wire)
	if err != nil {
		return nil, fmt.Errorf("rotate recover failed: %w", err)
	}
	return &RotateRecoverResult{Account: resp.Account, Action: resp.Action, GrantID: resp.GrantID, Recovery: resp.Recovery}, nil
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
	signerView, warnings, notes, err := a.eng.SignerRotatingStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("read signer status: %w", err)
	}
	byAccount := make(map[string]signerapi.RotatingAccountStatus, len(signerView))
	for _, s := range signerView {
		byAccount[s.Account] = s
	}
	result := &RotateStatusResult{}
	for _, address := range accounts {
		authorizer, err := a.eng.RefreshAuthAddressWithContext(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("read authorizer of %s: %w", address, err)
		}
		status := RotatingAccountStatus{Account: address, Authorizer: authorizerOrSelf(authorizer, address)}
		if s, ok := byAccount[address]; ok {
			status.Signer = &s
		}
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
