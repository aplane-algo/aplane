// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/engine"
)

// AppDeployRequest captures the parsed deploy request.
type AppDeployRequest struct {
	From             string
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	GlobalUint       uint64
	GlobalBytes      uint64
	LocalUint        uint64
	LocalBytes       uint64
	ExtraPages       uint32
	Note             string
	Wait             bool
	Fee              uint64
	UseFlatFee       bool
}

func (r AppDeployRequest) toEngineParams() engine.AppDeployParams {
	return engine.AppDeployParams{
		From: r.From,
		Approval: engine.AppProgramSource{
			Path:     r.ApprovalPath,
			Compiled: r.ApprovalCompiled,
		},
		Clear: engine.AppProgramSource{
			Path:     r.ClearPath,
			Compiled: r.ClearCompiled,
		},
		GlobalUint:   r.GlobalUint,
		GlobalBytes:  r.GlobalBytes,
		LocalUint:    r.LocalUint,
		LocalBytes:   r.LocalBytes,
		ExtraPages:   r.ExtraPages,
		Note:         r.Note,
		Fee:          r.Fee,
		UseFlatFee:   r.UseFlatFee,
		OnCompletion: types.NoOpOC,
	}
}

// AppDeploy executes the semantic part of an app deploy command.
func (a *App) AppDeploy(ctx context.Context, req AppDeployRequest) (*AppDeployResult, error) {
	fromAddr, err := a.eng.NewAddressResolver().ResolveSingle(req.From)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve deploy sender: %w", err)
	}
	req.From = fromAddr

	prepResult, err := a.eng.PrepareAppDeployWithContext(ctx, req.toEngineParams())
	if err != nil {
		return nil, err
	}
	prep := preparedTxnFromEngine(prepResult)

	submit, err := a.eng.SignAndSubmitWithContext(ctx, prep.enginePrep, req.Wait)
	if err != nil {
		return nil, fmt.Errorf("app deploy failed: %w", err)
	}

	result := &AppDeployResult{
		FromAddress:    fromAddr,
		SigningKeyType: prep.SigningContext.DisplayKeyType,
		Submitted:      !a.eng.GetSimulate(),
		Output:         submit.Output,
		PreSubmitLines: []string{fmt.Sprintf("Deploying app from {from} using %s...", prep.SigningContext.DisplayKeyType)},
		Structured: appresult.AppDeploy{
			TxID:      submit.TxID,
			Confirmed: submit.Confirmed,
		},
		Warnings: warningsFromTransactionWriteNotices(submit.WriteNotices),
	}

	if req.Wait && submit.Confirmed {
		createdResult, err := a.eng.LookupCreatedApplicationWithContext(ctx, submit.TxID)
		if err != nil {
			return nil, err
		}
		created := createdAppDetailsFromEngine(createdResult)
		result.Structured.AppID = created.AppID
		result.Structured.AppAddress = created.AppAddress
		result.ConfirmedLines = []string{fmt.Sprintf("Created app %d at %s", created.AppID, created.AppAddress)}
	}

	return result, nil
}
