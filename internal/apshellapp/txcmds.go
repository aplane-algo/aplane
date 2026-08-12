// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/partkeyparse"
	"github.com/aplane-algo/aplane/internal/signing"
)

// OptInRequest captures parsed opt-in inputs.
type OptInRequest struct {
	Account    string
	AssetRef   string
	Fee        uint64
	UseFlatFee bool
	LsigArgs   map[string][]byte
	Wait       bool
}

// OptOutRequest captures parsed opt-out inputs.
type OptOutRequest struct {
	Account    string
	AssetRef   string
	CloseTo    string
	Fee        uint64
	UseFlatFee bool
	LsigArgs   map[string][]byte
	Wait       bool
}

// KeyRegRequest captures parsed keyreg inputs.
type KeyRegRequest struct {
	Account           string
	Mode              string
	VoteKey           string
	SelectionKey      string
	StateProofKey     string
	VoteFirst         uint64
	VoteLast          uint64
	KeyDilution       uint64
	IncentiveEligible bool
	Wait              bool
	LsigArgs          map[string][]byte
}

// RekeyRequest captures parsed rekey inputs.
type RekeyRequest struct {
	Account    string
	Target     string
	Fee        uint64
	UseFlatFee bool
	LsigArgs   map[string][]byte
	Wait       bool
}

// UnrekeyRequest captures parsed unrekey inputs.
type UnrekeyRequest struct {
	Account    string
	Fee        uint64
	UseFlatFee bool
	LsigArgs   map[string][]byte
	Wait       bool
}

// CloseRequest captures parsed close inputs.
type CloseRequest struct {
	Account    string
	CloseTo    string
	Fee        uint64
	UseFlatFee bool
	LsigArgs   map[string][]byte
	Wait       bool
}

// SweepRequest captures parsed sweep inputs.
type SweepRequest struct {
	AssetRef    string
	FromRaw     []string
	ToRaw       string
	LeavingText string
	Fee         uint64
	UseFlatFee  bool
	LsigArgs    map[string][]byte
	Wait        bool
}

// ValidateRequest captures parsed account validation inputs.
type ValidateRequest struct {
	Account  string
	LsigArgs map[string][]byte
}

// ResolveIncentiveEligibility queries current status and resolves whether to charge the fee.
func (a *App) ResolveIncentiveEligibility(ctx context.Context, address string, requested bool) (*IncentiveEligibilityResult, error) {
	cache.Debug("checking incentive eligibility", "address", address)
	alreadyEligible, err := a.eng.GetIncentiveEligibility(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to query incentive eligibility: %w", err)
	}
	return &IncentiveEligibilityResult{
		AlreadyEligible: alreadyEligible,
		Requested:       requested,
		ChargeFee:       !alreadyEligible && requested,
	}, nil
}

// Validate resolves and validates one account or address set via 0-ALGO self-send transactions.
func (a *App) Validate(ctx context.Context, req ValidateRequest) (*ValidateCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	addresses, err := cmdspec.ResolveAddressList([]string{req.Account}, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve account: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses found for %q", req.Account)
	}

	result := &ValidateCommandResult{
		Input: req.Account,
		IsSet: len(req.Account) > 0 && req.Account[0] == '@',
	}
	for _, addr := range addresses {
		item := ValidateItemResult{Address: addr}
		prepResult, _, err := a.eng.PreparePayment(ctx, engine.SendPaymentParams{
			From:     addr,
			To:       addr,
			Amount:   0,
			LsigArgs: req.LsigArgs,
		})
		if err != nil {
			item.Error = fmt.Sprintf("failed to prepare: %v", err)
			result.FailureCount++
			result.Items = append(result.Items, item)
			continue
		}

		submit, err := a.eng.SignAndSubmit(ctx, prepResult, true)
		if err != nil {
			if submit != nil {
				item.TxID = submit.TxID
				item.Confirmed = submit.Confirmed
				item.Output = submit.Output
				item.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
			}
			if !errors.Is(err, engine.ErrSimulationFailed) {
				item.Error = err.Error()
			}
			result.FailureCount++
			result.Items = append(result.Items, item)
			continue
		}

		item.TxID = submit.TxID
		item.Confirmed = submit.Confirmed
		item.Output = submit.Output
		item.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
		result.SuccessCount++
		result.Items = append(result.Items, item)
	}

	decorateValidateResult(result)

	if result.FailureCount > 0 && result.SuccessCount == 0 {
		return result, fmt.Errorf("%d validation(s) failed", result.FailureCount)
	}
	if result.FailureCount > 0 {
		return result, fmt.Errorf("%d validation(s) failed", result.FailureCount)
	}
	return result, nil
}

func decorateValidateResult(result *ValidateCommandResult) {
	if result == nil {
		return
	}
	if len(result.Items) > 1 {
		result.SummaryLines = []string{
			"=== Validation Summary ===",
			fmt.Sprintf("Successful: %d/%d", result.SuccessCount, len(result.Items)),
			fmt.Sprintf("Failed: %d/%d", result.FailureCount, len(result.Items)),
		}
	}
}

// OptIn resolves and executes an ASA opt-in.
func (a *App) OptIn(ctx context.Context, req OptInRequest) (*OptInCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	address, err := cmdspec.ResolveSingleAddress(req.Account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	meta, err := cmdspec.ResolveAssetMetadata(a.Network(), req.AssetRef, a.eng.ASAResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve asset %q: %w", req.AssetRef, err)
	}

	prepResult, err := a.eng.PrepareOptIn(ctx, engine.OptInParams{
		Account:    address,
		AssetID:    meta.AssetID,
		Fee:        req.Fee,
		UseFlatFee: req.UseFlatFee,
		LsigArgs:   req.LsigArgs,
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("opt-in failed: %w", err)
	}

	return &OptInCommandResult{
		Account:        address,
		Asset:          meta,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		TxID:           submit.TxID,
		Confirmed:      submit.Confirmed,
		Output:         submit.Output,
		Warnings:       warningsFromTransactionWriteNotices(submit.WriteNotices),
	}, nil
}

// OptOut resolves and executes an ASA opt-out.
func (a *App) OptOut(ctx context.Context, req OptOutRequest) (*OptOutCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	accountAddr, err := cmdspec.ResolveSingleAddress(req.Account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve account %q: %w", req.Account, err)
	}

	meta, err := cmdspec.ResolveAssetMetadata(a.Network(), req.AssetRef, a.eng.ASAResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve asset %q: %w", req.AssetRef, err)
	}

	var closeToAddr string
	if req.CloseTo != "" {
		closeToAddr, err = cmdspec.ResolveSingleAddress(req.CloseTo, resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve close-to address %q: %w", req.CloseTo, err)
		}
	}

	prepResult, checkResult, err := a.eng.PrepareOptOut(ctx, engine.OptOutParams{
		Account:    accountAddr,
		AssetID:    meta.AssetID,
		CloseTo:    closeToAddr,
		Fee:        req.Fee,
		UseFlatFee: req.UseFlatFee,
		LsigArgs:   req.LsigArgs,
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)
	check := optOutCheckDetailsFromEngine(checkResult)

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("opt-out failed: %w", err)
	}

	return &OptOutCommandResult{
		Account:        accountAddr,
		CloseTo:        closeToAddr,
		Asset:          meta,
		AssetBalance:   check.AssetBalance,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		TxID:           submit.TxID,
		Confirmed:      submit.Confirmed,
		Output:         submit.Output,
		Warnings:       warningsFromTransactionWriteNotices(submit.WriteNotices),
	}, nil
}

// KeyReg prepares and executes a key registration transaction.
func (a *App) KeyReg(ctx context.Context, req KeyRegRequest) (*KeyRegCommandResult, error) {
	mode := req.Mode
	voteKey := req.VoteKey
	selectionKey := req.SelectionKey
	stateProofKey := req.StateProofKey
	voteFirst := req.VoteFirst
	voteLast := req.VoteLast
	keyDilution := req.KeyDilution
	if mode == "offline" {
		voteKey = ""
		selectionKey = ""
		stateProofKey = ""
		voteFirst = 0
		voteLast = 0
		keyDilution = 0
	}

	resolver := a.eng.NewAddressResolver()
	address, err := cmdspec.ResolveSingleAddress(req.Account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	prepResult, err := a.eng.PrepareKeyReg(ctx, engine.KeyRegParams{
		Account:           address,
		Mode:              mode,
		VoteKey:           voteKey,
		SelectionKey:      selectionKey,
		StateProofKey:     stateProofKey,
		VoteFirst:         voteFirst,
		VoteLast:          voteLast,
		KeyDilution:       keyDilution,
		IncentiveEligible: req.IncentiveEligible,
		LsigArgs:          req.LsigArgs,
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("key registration failed: %w", err)
	}

	return &KeyRegCommandResult{
		Account:        address,
		Mode:           mode,
		VoteFirst:      voteFirst,
		VoteLast:       voteLast,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		TxID:           submit.TxID,
		Confirmed:      submit.Confirmed,
		Output:         submit.Output,
		Warnings:       warningsFromTransactionWriteNotices(submit.WriteNotices),
	}, nil
}

// KeyRegFromPartKey prepares and submits online keyreg from parsed goal output.
func (a *App) KeyRegFromPartKey(ctx context.Context, parsed *partkeyparse.ParsedInfo, incentiveEligible bool) (*KeyRegCommandResult, error) {
	prepResult, err := a.eng.PrepareKeyReg(ctx, engine.KeyRegParams{
		Account:           parsed.ParentAddress,
		Mode:              "online",
		VoteKey:           parsed.VoteKey,
		SelectionKey:      parsed.SelectionKey,
		StateProofKey:     parsed.StateProofKey,
		VoteFirst:         parsed.VoteFirst,
		VoteLast:          parsed.VoteLast,
		KeyDilution:       parsed.KeyDilution,
		IncentiveEligible: incentiveEligible,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to prepare keyreg: %w", err)
	}
	prep := preparedTxnFromEngine(prepResult)

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, false)
	if err != nil {
		return nil, fmt.Errorf("key registration failed: %w", err)
	}

	confirmed := false
	output := submit.Output
	if !a.eng.GetSimulate() {
		confirmation, err := a.eng.WaitForConfirmationResult(ctx, submit.TxID, 9)
		if confirmation != nil {
			output += confirmation.Output
		}
		if err != nil {
			return nil, err
		}
		confirmed = true
	}

	return &KeyRegCommandResult{
		Account:        parsed.ParentAddress,
		Mode:           "online",
		VoteFirst:      parsed.VoteFirst,
		VoteLast:       parsed.VoteLast,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		TxID:           submit.TxID,
		Confirmed:      confirmed,
		Output:         output,
		Warnings:       warningsFromTransactionWriteNotices(submit.WriteNotices),
	}, nil
}

// ListRekeys returns all cached rekey relationships.
func (a *App) ListRekeys(_ context.Context) (*RekeyListCommandResult, error) {
	return &RekeyListCommandResult{Rekeys: rekeyEntryListFromEngine(a.eng.ListRekeyedAccounts())}, nil
}

// RefreshAuthCache refreshes cached auth-address relationships.
func (a *App) RefreshAuthCache(ctx context.Context) error {
	return a.eng.RefreshAuthCache(ctx)
}

// RefreshAuthAddress refreshes the cached auth-address relationship for one account.
func (a *App) RefreshAuthAddress(ctx context.Context, account string) (*AuthRefreshCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	address, err := cmdspec.ResolveSingleAddress(account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}
	authAddress, err := a.eng.RefreshAuthAddressWithContext(ctx, address)
	if err != nil {
		return nil, err
	}
	return &AuthRefreshCommandResult{
		Address:     address,
		AuthAddress: authAddress,
		IsRekeyed:   authAddress != "" && authAddress != address,
	}, nil
}

// Rekey prepares and executes a rekey transaction.
func (a *App) Rekey(ctx context.Context, req RekeyRequest) (*RekeyCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	fromAddress, err := cmdspec.ResolveSingleAddress(req.Account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve from address: %w", err)
	}
	toAddress, err := cmdspec.ResolveSingleAddress(req.Target, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve to address: %w", err)
	}

	prepResult, checkResult, err := a.eng.PrepareRekey(ctx, engine.RekeyParams{
		From:       fromAddress,
		To:         toAddress,
		Fee:        req.Fee,
		UseFlatFee: req.UseFlatFee,
		LsigArgs:   req.LsigArgs,
	})
	if err != nil {
		check := rekeyCheckDetailsFromEngine(checkResult)
		if check != nil && check.TargetIsRekeyed {
			return nil, fmt.Errorf("policy rejection: cannot rekey to %s because it is itself rekeyed to %s", toAddress, check.TargetAuthAddr)
		}
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)
	check := rekeyCheckDetailsFromEngine(checkResult)

	canSignForTarget, authorizationKind := a.eng.CanSignForAddressWithKind(toAddress)
	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("rekey transaction failed: %w", err)
	}

	result := &RekeyCommandResult{
		From:                    fromAddress,
		To:                      toAddress,
		IsUnrekey:               check.IsUnrekey,
		CanSignForTarget:        canSignForTarget,
		TargetIsLsig:            authorizationKind == algorithm.AuthorizationLogicSig,
		TargetAuthorizationKind: authorizationKind,
		TxID:                    submit.TxID,
		Confirmed:               submit.Confirmed,
		Output:                  submit.Output,
		Warnings:                warningsFromTransactionWriteNotices(submit.WriteNotices),
	}
	// The auth-cache refresh after a confirmed rekey happens in the engine submit
	// path (SignAndSubmit -> refreshRekeyedSenders), so every caller — REPL, JS,
	// MCP — stays consistent without duplicating it. Surface its non-fatal warning.
	result.RefreshWarning = submit.AuthRefreshWarning
	decorateRekeyResult(result)
	return result, nil
}

// Unrekey prepares and executes a rekey-back-to-self transaction.
func (a *App) Unrekey(ctx context.Context, req UnrekeyRequest) (*RekeyCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	address, err := cmdspec.ResolveSingleAddress(req.Account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	balanceEngineResult, err := a.eng.GetAccountBalanceRaw(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to query account info: %w", err)
	}
	balanceResult := balanceDetailsFromEngine(balanceEngineResult)
	if balanceResult.AuthAddr == "" || balanceResult.AuthAddr == address {
		return nil, fmt.Errorf("account is not rekeyed (it already signs for itself)")
	}

	prepResult, _, err := a.eng.PrepareRekey(ctx, engine.RekeyParams{
		From:       address,
		To:         address,
		Fee:        req.Fee,
		UseFlatFee: req.UseFlatFee,
		LsigArgs:   req.LsigArgs,
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("unrekey transaction failed: %w", err)
	}

	result := &RekeyCommandResult{
		From:               address,
		To:                 address,
		IsUnrekey:          true,
		CurrentAuthAddress: balanceResult.AuthAddr,
		TxID:               submit.TxID,
		Confirmed:          submit.Confirmed,
		Output:             submit.Output,
		Warnings:           warningsFromTransactionWriteNotices(submit.WriteNotices),
	}
	// See App.Rekey: the engine submit path performs the refresh; surface its warning.
	result.RefreshWarning = submit.AuthRefreshWarning
	decorateRekeyResult(result)
	return result, nil
}

func decorateRekeyResult(result *RekeyCommandResult) {
	if result == nil {
		return
	}
	if result.IsUnrekey {
		result.PreSubmitLines = []string{
			"Account is currently rekeyed to: {current_auth}",
			"Unrekeying account {from} (back to itself)...",
		}
		result.ConfirmedLines = []string{
			"Account {from} is now back to normal (no rekey in effect)",
		}
		result.PendingLines = []string{
			"When confirmed, {from} will sign for itself again",
		}
		return
	}

	if result.CanSignForTarget {
		targetKind := "Ed25519"
		switch result.TargetAuthorizationKind {
		case algorithm.AuthorizationNativePQ:
			targetKind = "native post-quantum"
		case algorithm.AuthorizationLogicSig:
			targetKind = "lsig"
		default:
			if result.TargetIsLsig {
				targetKind = "lsig"
			}
		}
		result.PreSubmitLines = []string{
			fmt.Sprintf("Rekeying account {from} to %s address {to}...", targetKind),
			"WARNING: After this transaction, you must use the new auth address to sign!",
		}
		switch targetKind {
		case "lsig":
			result.ConfirmedLines = []string{
				"Account {from} is now rekeyed to lsig {to}",
			}
			result.PendingLines = []string{
				"When confirmed, {from} will be rekeyed to lsig {to}",
			}
		case "native post-quantum":
			result.ConfirmedLines = []string{
				"Account {from} is now rekeyed to native post-quantum address {to}",
			}
			result.PendingLines = []string{
				"When confirmed, {from} will be rekeyed to native post-quantum address {to}",
			}
		default:
			result.ConfirmedLines = []string{
				"Account {from} is now rekeyed to Ed25519 address {to}",
			}
			result.PendingLines = []string{
				"When confirmed, {from} will be rekeyed to Ed25519 address {to}",
			}
		}
		return
	}

	result.PreSubmitLines = []string{
		"WARNING: Rekeying to Address You Cannot Sign For!",
		"Target address: {to}",
		"",
		"This system cannot sign for this target address.",
		"After rekeying, you will NOT be able to sign transactions from this account using this system.",
		"",
		"You will need:",
		"  - The private key for the target address, OR",
		"  - Another way to authorize transactions",
		"",
		"This operation cannot be easily reversed!",
		"Proceeding with rekey to {to}...",
		"(You will be asked to approve at Signer)",
		"WARNING: After this transaction, you must use the new auth address to sign!",
	}
	result.ConfirmedLines = []string{
		"Account rekeyed to address you cannot sign for.",
		"Your system can no longer sign transactions for this account.",
		"To regain control, you'll need to sign with the new auth address.",
	}
	result.PendingLines = []string{
		"Target is an address you cannot sign for - you'll need the new auth address's private key to sign.",
	}
}

// Close prepares and executes an account close transaction.
func (a *App) Close(ctx context.Context, req CloseRequest) (*CloseCommandResult, error) {
	resolver := a.eng.NewAddressResolver()
	fromAddress, err := cmdspec.ResolveSingleAddress(req.Account, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source address %q: %w", req.Account, err)
	}
	toAddress, err := cmdspec.ResolveSingleAddress(req.CloseTo, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve destination address %q: %w", req.CloseTo, err)
	}
	if fromAddress == toAddress {
		return nil, fmt.Errorf("cannot close account to itself")
	}

	prepResult, checkResult, err := a.eng.PrepareClose(ctx, engine.CloseAccountParams{
		From:       fromAddress,
		CloseTo:    toAddress,
		Fee:        req.Fee,
		UseFlatFee: req.UseFlatFee,
		LsigArgs:   req.LsigArgs,
	})
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)
	check := closeCheckDetailsFromEngine(checkResult)

	submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("close failed: %w", err)
	}

	result := &CloseCommandResult{
		From:           fromAddress,
		CloseTo:        toAddress,
		Balance:        check.Balance,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		TxID:           submit.TxID,
		Confirmed:      submit.Confirmed,
		Output:         submit.Output,
		Warnings:       warningsFromTransactionWriteNotices(submit.WriteNotices),
	}
	decorateCloseResult(result)
	return result, nil
}

func decorateCloseResult(result *CloseCommandResult) {
	if result == nil {
		return
	}
	balanceAlgo := float64(result.Balance) / 1000000.0
	result.PreSubmitLines = []string{
		fmt.Sprintf("Closing account {from} (%.6f ALGO) to {to} using %s...", balanceAlgo, result.SigningKeyType),
	}
	result.ConfirmedLines = []string{
		"Account {from} closed to {to}",
	}
}

// Sweep resolves and executes a sweep flow across one or more source accounts.
func (a *App) Sweep(ctx context.Context, req SweepRequest) (*SweepCommandResult, error) {
	resolver := a.eng.NewAddressResolver()

	var fromAddresses []string
	usedAllSignable := false
	if req.FromRaw == nil {
		fromAddresses = a.eng.GetSignableAddresses()
		usedAllSignable = true
		if len(fromAddresses) == 0 {
			return nil, fmt.Errorf("no signable accounts available. Connect to Signer first or specify accounts with: sweep <asset> from [account1 account2] to <dest>")
		}
	} else {
		var err error
		fromAddresses, err = cmdspec.ResolveAddressList(req.FromRaw, resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve source addresses: %w", err)
		}
	}

	toAddress, err := cmdspec.ResolveSingleAddress(req.ToRaw, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve destination address: %w", err)
	}

	assetMeta, err := cmdspec.ResolveAssetMetadata(a.Network(), req.AssetRef, a.eng.ASAResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve asset %q: %w", req.AssetRef, err)
	}

	receiverOptedIn := false
	if assetMeta.AssetID != 0 {
		receiverEngineBalance, err := a.eng.GetAccountBalanceRaw(ctx, toAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get receiver account info: %w", err)
		}
		receiverBalance := balanceDetailsFromEngine(receiverEngineBalance)
		for _, asset := range receiverBalance.Assets {
			if asset.AssetID == assetMeta.AssetID {
				receiverOptedIn = true
				break
			}
		}
		if !receiverOptedIn {
			return nil, fmt.Errorf("receiver %s is not opted into ASA %d (%s)", toAddress, assetMeta.AssetID, asa.DisplayRef(assetMeta))
		}
	}

	leavingAmount, err := cmdspec.ResolveAssetAmount(a.Network(), req.AssetRef, req.LeavingText, a.eng.ASAResolver())
	if err != nil {
		return nil, fmt.Errorf("failed to convert leaving amount: %w", err)
	}

	result := &SweepCommandResult{
		Asset:           assetMeta,
		Leaving:         leavingAmount,
		FromAddresses:   fromAddresses,
		ToAddress:       toAddress,
		UsedAllSignable: usedAllSignable,
		ReceiverOptedIn: receiverOptedIn,
	}

	for _, fromAddress := range fromAddresses {
		item := SweepItemResult{From: fromAddress, To: toAddress}
		if fromAddress == toAddress {
			item.SkippedReason = "source and destination are the same account"
			result.Items = append(result.Items, item)
			continue
		}

		balanceEngineResult, err := a.eng.GetAccountBalanceRaw(ctx, fromAddress)
		if err != nil {
			item.Error = fmt.Sprintf("failed to get account info: %v", err)
			result.FailureCount++
			result.Items = append(result.Items, item)
			continue
		}
		balanceResult := balanceDetailsFromEngine(balanceEngineResult)

		var balance uint64
		if assetMeta.AssetID == 0 {
			balance = balanceResult.AlgoBalance
		} else {
			found := false
			for _, asset := range balanceResult.Assets {
				if asset.AssetID == assetMeta.AssetID {
					balance = asset.Amount
					found = true
					break
				}
			}
			if !found {
				item.SkippedReason = fmt.Sprintf("account not opted into %s", asa.DisplayRef(assetMeta))
				result.Items = append(result.Items, item)
				continue
			}
		}

		authorizationReserve, err := a.eng.AuthorizationFeeReserve(ctx, fromAddress)
		if err != nil {
			item.Error = fmt.Sprintf("failed to plan authorization fee reserve: %v", err)
			result.FailureCount++
			result.Items = append(result.Items, item)
			continue
		}
		sendAmount, feeReserve, ok := sweepSendAmount(balance, leavingAmount.Raw, assetMeta.AssetID, req.Fee, req.UseFlatFee, authorizationReserve)
		if !ok {
			item.SkippedReason = fmt.Sprintf("balance %d <= leaving amount %d", balance, leavingAmount.Raw)
			if assetMeta.AssetID == 0 && balance > leavingAmount.Raw {
				item.SkippedReason = fmt.Sprintf("balance %d cannot cover leaving amount %d plus fee reserve %d", balance, leavingAmount.Raw, feeReserve)
			}
			result.Items = append(result.Items, item)
			continue
		}

		item.Amount = asa.AmountFromRaw(sendAmount, assetMeta)
		var prep *PreparedTxn
		if assetMeta.AssetID == 0 {
			prepResult, _, prepErr := a.eng.PreparePayment(ctx, engine.SendPaymentParams{
				From:       fromAddress,
				To:         toAddress,
				Amount:     item.Amount.Raw,
				Fee:        req.Fee,
				UseFlatFee: req.UseFlatFee,
				LsigArgs:   req.LsigArgs,
			})
			prep = preparedTxnFromEngine(prepResult)
			err = prepErr
		} else {
			prepResult, _, prepErr := a.eng.PrepareASATransfer(ctx, engine.SendASAParams{
				From:       fromAddress,
				To:         toAddress,
				AssetID:    assetMeta.AssetID,
				Amount:     item.Amount.Raw,
				Fee:        req.Fee,
				UseFlatFee: req.UseFlatFee,
				LsigArgs:   req.LsigArgs,
			})
			prep = preparedTxnFromEngine(prepResult)
			err = prepErr
		}
		if err != nil {
			item.Error = fmt.Sprintf("failed to prepare transaction: %v", err)
			result.FailureCount++
			result.Items = append(result.Items, item)
			continue
		}

		submit, err := a.eng.SignAndSubmit(ctx, prep.enginePrep, req.Wait)
		if err != nil {
			if submit != nil {
				item.TxID = submit.TxID
				item.Confirmed = submit.Confirmed
				item.Output = submit.Output
				item.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
			}
			if !errors.Is(err, engine.ErrSimulationFailed) {
				item.Error = fmt.Sprintf("transaction failed: %v", err)
			}
			result.FailureCount++
			result.Items = append(result.Items, item)
			continue
		}

		item.TxID = submit.TxID
		item.Confirmed = submit.Confirmed
		item.Output = submit.Output
		item.Warnings = warningsFromTransactionWriteNotices(submit.WriteNotices)
		result.LastTxID = submit.TxID
		result.SuccessCount++
		result.Items = append(result.Items, item)
	}

	decorateSweepResult(result)

	if result.FailureCount > 0 && result.SuccessCount == 0 {
		return result, fmt.Errorf("all %d transaction(s) failed", result.FailureCount)
	}
	return result, nil
}

// sweepSendAmount computes how much to send so the account is left with exactly
// `leaving`. For ALGO sweeps the fee reserve is the base transaction fee plus
// authorizationFeeReserve — LogicSig dummy/program fees or the native-PQ fee
// contribution — so sweeping from a non-Ed25519 account does not overspend.
// ASA sweeps pay their fee from the ALGO balance, not the swept asset, so the
// authorization reserve does not apply there.
func sweepSendAmount(balance, leaving, assetID, fee uint64, useFlatFee bool, authorizationFeeReserve uint64) (amount uint64, feeReserve uint64, ok bool) {
	if balance <= leaving {
		return 0, 0, false
	}
	available := balance - leaving
	if assetID != 0 {
		return available, 0, true
	}
	// A flat fee is authoritative when opted in, including an explicit flat
	// zero, matching the unified fee model (engine.getSuggestedParamsWithFee).
	baseFee := uint64(signing.DefaultMinFee)
	if useFlatFee {
		baseFee = fee
	}
	if authorizationFeeReserve > math.MaxUint64-baseFee {
		return 0, math.MaxUint64, false
	}
	feeReserve = baseFee + authorizationFeeReserve
	if available <= feeReserve {
		return 0, feeReserve, false
	}
	return available - feeReserve, feeReserve, true
}

func decorateSweepResult(result *SweepCommandResult) {
	if result == nil {
		return
	}

	if result.UsedAllSignable {
		result.InfoLines = append(result.InfoLines,
			"No source accounts specified, using all signable accounts...",
			fmt.Sprintf("Found %d signable account(s): {from_addresses}", len(result.FromAddresses)),
		)
	}
	if result.ReceiverOptedIn {
		result.InfoLines = append(result.InfoLines,
			fmt.Sprintf("Receiver is opted into %s ✓", asa.DisplayRef(result.Asset)),
		)
	}

	result.HeaderLine = fmt.Sprintf("Sweeping %s from %d account(s) to {to}", asa.DisplayRef(result.Asset), len(result.FromAddresses))
	if result.Leaving.Raw > 0 {
		result.HeaderLine += fmt.Sprintf(" (leaving %s in each)", asa.DisplayString(result.Leaving))
	}

	result.SummaryLines = []string{
		fmt.Sprintf("Sweep complete: %d succeeded, %d failed", result.SuccessCount, result.FailureCount),
	}
	if result.SuccessCount > 0 && result.LastTxID != "" {
		result.SummaryLines = append(result.SummaryLines, fmt.Sprintf("Last transaction: %s", result.LastTxID))
	}
}
