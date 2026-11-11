// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"slices"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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
	// The list is sent as given, so a zero is refused, not dropped: dropping
	// it would move every app listed after it.
	for i, appID := range params.ForeignApps {
		if appID == 0 {
			return nil, fmt.Errorf("invalid foreign app %d: app id must be non-zero", i+1)
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
		0, // app version (v42 SDK; zero preserves legacy behavior)
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

// ensureAppReferences returns the call's foreign apps: the caller's list
// exactly as given, then any app a box reference needs that the list lacks.
//
// The caller's entries are kept in order, duplicates and the called app
// included. A program reads them by position (`txna Applications N`), so
// tidying the list would move the apps it expects.
//
// Which entry a box then points at is the Algorand SDK's rule
// (`parseBoxReferences`), not decided here:
//   - a box with app ID 0 is the called app's and is always index 0. The
//     parsers give a box written without an app ID this form, so its bytes
//     don't depend on whether the called app is also listed;
//   - a box with an app ID points at the first entry in the list that
//     matches, and at index 0 when the ID is the called app's and the list
//     doesn't have it.
//
// TestPrepareAppCallRaw_SuccessIncludesReferencesAndLsigArgs pins all three.
func ensureAppReferences(curAppID uint64, foreignApps []uint64, boxes []types.AppBoxReference) []uint64 {
	result := make([]uint64, len(foreignApps), len(foreignApps)+len(boxes))
	copy(result, foreignApps)

	for _, box := range boxes {
		// A box of the called app needs no entry added: the SDK resolves it
		// to the called app's listed position, or to index 0 when unlisted.
		if box.AppID == 0 || box.AppID == curAppID || slices.Contains(result, box.AppID) {
			continue
		}
		result = append(result, box.AppID)
	}

	return result
}
