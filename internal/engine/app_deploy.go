// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// AppProgramSource describes a TEAL source file or compiled AVM bytecode file.
type AppProgramSource struct {
	Path     string
	Compiled bool
}

// AppDeployParams describes an application creation transaction.
type AppDeployParams struct {
	From         string
	Approval     AppProgramSource
	Clear        AppProgramSource
	GlobalUint   uint64
	GlobalBytes  uint64
	LocalUint    uint64
	LocalBytes   uint64
	ExtraPages   uint32
	Note         string
	Fee          uint64
	UseFlatFee   bool
	LsigArgs     map[string][]byte
	OnCompletion types.OnCompletion
}

// AppDeployResult describes a submitted app creation transaction.
type AppDeployResult struct {
	TxID       string `json:"tx_id"`
	Confirmed  bool   `json:"confirmed"`
	AppID      uint64 `json:"app_id,omitempty"`
	AppAddress string `json:"app_address,omitempty"`
}

// PrepareAppDeploy prepares an application creation transaction
// using the caller's context for algod lookups and compilation.
func (e *Engine) PrepareAppDeploy(ctx context.Context, params AppDeployParams) (*TransactionPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if params.From == "" {
		return nil, fmt.Errorf("missing deploy sender")
	}
	if params.Approval.Path == "" {
		return nil, fmt.Errorf("missing approval program")
	}
	if params.Clear.Path == "" {
		return nil, fmt.Errorf("missing clear program")
	}

	signingCtx, err := e.BuildSigningContext(ctx, params.From)
	if err != nil {
		return nil, err
	}

	approvalProgram, err := e.loadAppProgram(ctx, params.Approval)
	if err != nil {
		return nil, fmt.Errorf("failed to load approval program: %w", err)
	}
	clearProgram, err := e.loadAppProgram(ctx, params.Clear)
	if err != nil {
		return nil, fmt.Errorf("failed to load clear program: %w", err)
	}

	sp, err := e.AlgodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %w", err)
	}
	// Apply a flat fee whenever the caller opts in, including an explicit flat
	// zero, matching the unified fee model used by send and getSuggestedParams.
	if params.UseFlatFee {
		sp.FlatFee = true
		sp.Fee = types.MicroAlgos(params.Fee)
	}

	sender, err := types.DecodeAddress(signingCtx.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	txn, err := transaction.MakeApplicationCallTxWithBoxes(
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
		params.OnCompletion,
		approvalProgram,
		clearProgram,
		types.StateSchema{NumUint: params.GlobalUint, NumByteSlice: params.GlobalBytes},
		types.StateSchema{NumUint: params.LocalUint, NumByteSlice: params.LocalBytes},
		params.ExtraPages,
		0, // app version (v42 SDK; zero preserves legacy behavior)
		sp,
		sender,
		[]byte(params.Note),
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to construct app deploy transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txn,
		SigningContext: signingCtx,
		LsigArgs:       params.LsigArgs,
	}, nil
}

func (e *Engine) LookupCreatedApplication(ctx context.Context, txID string) (*AppDeployResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if txID == "" {
		return nil, fmt.Errorf("missing transaction id")
	}

	info, _, err := e.AlgodClient.PendingTransactionInformation(txID).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending transaction: %w", err)
	}
	if info.ApplicationIndex == 0 {
		return nil, fmt.Errorf("transaction did not create an application")
	}

	return &AppDeployResult{
		TxID:       txID,
		Confirmed:  info.ConfirmedRound > 0,
		AppID:      info.ApplicationIndex,
		AppAddress: crypto.GetApplicationAddress(info.ApplicationIndex).String(),
	}, nil
}

func (e *Engine) loadAppProgram(ctx context.Context, src AppProgramSource) ([]byte, error) {
	programBytes, err := os.ReadFile(src.Path)
	if err != nil {
		return nil, err
	}
	if src.Compiled {
		return programBytes, nil
	}

	result, err := e.AlgodClient.TealCompile(programBytes).Do(ctx)
	if err != nil {
		return nil, err
	}
	compiled, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode compiled program: %w", err)
	}
	return compiled, nil
}
