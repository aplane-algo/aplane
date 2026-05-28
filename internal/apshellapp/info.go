// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

func statusDetailsFromEngine(result *engine.StatusResult) StatusDetails {
	if result == nil {
		return StatusDetails{}
	}
	return StatusDetails{
		Network:          result.Network,
		IsConnected:      result.IsConnected,
		ConnectionTarget: result.ConnectionTarget,
		WriteMode:        result.WriteMode,
		ASACacheCount:    result.ASACacheCount,
		AliasCacheCount:  result.AliasCacheCount,
		SetCacheCount:    result.SetCacheCount,
		SignerCacheCount: result.SignerCacheCount,
	}
}

func accountSummaryFromEngine(account engine.AccountInfo) AccountSummary {
	return AccountSummary{
		Address:    account.Address,
		Alias:      account.Alias,
		Source:     account.Source,
		IsSignable: account.IsSignable,
		KeyType:    account.KeyType,
	}
}

func accountSummaryListFromEngine(accounts []engine.AccountInfo) []AccountSummary {
	result := make([]AccountSummary, len(accounts))
	for i, account := range accounts {
		result[i] = accountSummaryFromEngine(account)
	}
	return result
}

func participationDetailsFromEngine(result *engine.ParticipationResult) ParticipationDetails {
	if result == nil {
		return ParticipationDetails{}
	}
	return ParticipationDetails{
		Address:           result.Address,
		IsOnline:          result.IsOnline,
		VoteKey:           result.VoteKey,
		SelectionKey:      result.SelectionKey,
		StateProofKey:     result.StateProofKey,
		VoteFirstValid:    result.VoteFirstValid,
		VoteLastValid:     result.VoteLastValid,
		VoteKeyDilution:   result.VoteKeyDilution,
		IncentiveEligible: result.IncentiveEligible,
	}
}

// Status returns structured status information for rendering by the shell.
func (a *App) Status(_ context.Context) (*StatusCommandResult, error) {
	return &StatusCommandResult{
		Status:          statusDetailsFromEngine(a.eng.GetStatus()),
		LogicSigTypes:   logicsigdsa.GetKeyTypes(),
		Algorithms:      algorithm.GetRegisteredFamilies(),
		TunnelConnected: a.IsTunnelConnected(),
	}, nil
}

// Accounts returns the set of known accounts for rendering by the shell.
func (a *App) Accounts(_ context.Context) (*AccountsCommandResult, error) {
	accounts, err := a.eng.ListAccounts()
	if err != nil {
		return nil, err
	}
	return &AccountsCommandResult{Accounts: accountSummaryListFromEngine(accounts)}, nil
}

// Holders resolves the holders command semantics while leaving presentation to the shell.
func (a *App) Holders(ctx context.Context, args []string) (*HoldersCommandResult, error) {
	assetRef := "algo"
	if len(args) > 1 {
		return nil, fmt.Errorf("usage: holders [asa|algo]")
	}
	if len(args) == 1 {
		assetRef = args[0]
	}

	addresses, err := a.eng.ListAllAddresses()
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no accounts found (add aliases or connect to signer)")
	}

	holders, err := a.eng.GetHoldersWithContext(ctx, assetRef)
	if err != nil {
		return nil, err
	}
	var warnings []Warning
	if holders.QueryErrors > 0 {
		warnings = append(warnings, Warning{
			Code:    "holder_query_failed",
			Message: fmt.Sprintf("%d account(s) could not be queried", holders.QueryErrors),
		})
	}

	return &HoldersCommandResult{
		Addresses: holders.Addresses,
		AssetRef:  assetRef,
		Warnings:  warnings,
	}, nil
}

// Participation resolves the participation command semantics while leaving presentation to the shell.
func (a *App) Participation(ctx context.Context, args []string) (*ParticipationCommandResult, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: participation <address|alias>")
	}

	participationResult, err := a.eng.GetParticipationStatusWithContext(ctx, args[0])
	if err != nil {
		return nil, err
	}
	participation := participationDetailsFromEngine(participationResult)

	isRekeyed, authAddr := a.eng.IsRekeyed(participation.Address)
	return &ParticipationCommandResult{
		Participation: participation,
		IsRekeyed:     isRekeyed,
		AuthAddress:   authAddr,
	}, nil
}
