// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// RawAppCallParams contains parameters for constructing a raw application call.
// All addresses must be resolved 58-character Algorand addresses.
type RawAppCallParams struct {
	AppID         uint64
	From          string
	AppArgs       [][]byte
	Accounts      []string
	ForeignApps   []uint64
	ForeignAssets []uint64
	Boxes         []types.AppBoxReference
	OnCompletion  types.OnCompletion
	Approval      AppProgramSource
	Clear         AppProgramSource
	Note          string
	Fee           uint64
	UseFlatFee    bool
	LsigArgs      map[string][]byte
}

type MethodAppCallParams struct {
	ABIPath string
	Method  string
	Args    []string
	RawAppCallParams
}

type PreparedMethodAppCall struct {
	Prep   *TransactionPrepResult
	Method appspec.Method
}

// PrepareAppCallRaw validates and prepares a raw application call
// transaction using the caller's context for algod lookups and compilation.
func (e *Engine) PrepareAppCallRaw(ctx context.Context, params RawAppCallParams) (*TransactionPrepResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if params.AppID == 0 {
		return nil, fmt.Errorf("missing application id")
	}
	for i, account := range params.Accounts {
		if _, err := types.DecodeAddress(account); err != nil {
			return nil, fmt.Errorf("invalid account %d address: %w", i+1, err)
		}
	}
	for i, assetID := range params.ForeignAssets {
		if assetID == 0 {
			return nil, fmt.Errorf("invalid foreign asset %d: asset id must be non-zero", i+1)
		}
	}
	for i, box := range params.Boxes {
		if len(box.Name) == 0 {
			return nil, fmt.Errorf("invalid box %d name: box name must be non-empty", i+1)
		}
	}

	signingCtx, err := e.BuildSigningContext(ctx, params.From)
	if err != nil {
		return nil, err
	}

	sp, err := e.getSuggestedParamsWithFee(ctx, params.Fee, params.UseFlatFee)
	if err != nil {
		return nil, err
	}

	sender, err := types.DecodeAddress(params.From)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	foreignApps := ensureAppReferences(params.AppID, params.ForeignApps, params.Boxes)
	var approvalProgram []byte
	var clearProgram []byte

	switch params.OnCompletion {
	case types.UpdateApplicationOC:
		if params.Approval.Path == "" {
			return nil, fmt.Errorf("missing approval program for app update")
		}
		if params.Clear.Path == "" {
			return nil, fmt.Errorf("missing clear program for app update")
		}
		approvalProgram, err = e.loadAppProgram(ctx, params.Approval)
		if err != nil {
			return nil, fmt.Errorf("failed to load approval program: %w", err)
		}
		clearProgram, err = e.loadAppProgram(ctx, params.Clear)
		if err != nil {
			return nil, fmt.Errorf("failed to load clear program: %w", err)
		}
	default:
		if params.Approval.Path != "" || params.Clear.Path != "" {
			return nil, fmt.Errorf("approval and clear programs are only supported with oncomp=update")
		}
	}

	txnObj, err := transaction.MakeApplicationCallTxWithBoxes(
		params.AppID,
		params.AppArgs,
		params.Accounts,
		foreignApps,
		params.ForeignAssets,
		params.Boxes,
		params.OnCompletion,
		approvalProgram,
		clearProgram,
		types.StateSchema{},
		types.StateSchema{},
		0,
		sp,
		sender,
		[]byte(params.Note),
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create application call transaction: %w", err)
	}

	return &TransactionPrepResult{
		Transaction:    txnObj,
		SigningContext: signingCtx,
		LsigArgs:       params.LsigArgs,
		AppCallInfo:    &appspecAppCallInfoRaw,
	}, nil
}

func (e *Engine) PrepareAppCallMethod(ctx context.Context, params MethodAppCallParams) (*PreparedMethodAppCall, error) {
	if params.ABIPath == "" {
		return nil, fmt.Errorf("ABI path is required")
	}

	spec, err := appspec.Load(params.ABIPath)
	if err != nil {
		return nil, err
	}

	method, err := spec.ResolveMethod(params.Method)
	if err != nil {
		return nil, err
	}

	encodedArgs, err := method.EncodeArgs(params.Args)
	if err != nil {
		return nil, err
	}

	rawParams := params.RawAppCallParams
	rawParams.AppArgs = encodedArgs

	prep, err := e.PrepareAppCallRaw(ctx, rawParams)
	if err != nil {
		return nil, err
	}
	prep.AppCallInfo = &signerapi.AppCallInfo{
		Mode:   "abi",
		Method: method.Signature(),
	}

	return &PreparedMethodAppCall{
		Prep:   prep,
		Method: *method,
	}, nil
}

var appspecAppCallInfoRaw = signerapi.AppCallInfo{Mode: "raw"}

func ensureAppReferences(curAppID uint64, foreignApps []uint64, boxes []types.AppBoxReference) []uint64 {
	seen := make(map[uint64]bool, len(foreignApps))
	result := make([]uint64, 0, len(foreignApps))

	for _, appID := range foreignApps {
		if appID == 0 || appID == curAppID || seen[appID] {
			continue
		}
		seen[appID] = true
		result = append(result, appID)
	}

	for _, box := range boxes {
		if box.AppID == 0 || box.AppID == curAppID || seen[box.AppID] {
			continue
		}
		seen[box.AppID] = true
		result = append(result, box.AppID)
	}

	return result
}
