// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (s Service) SignGroup(ctx context.Context, ir *identity.Runtime, req signerapi.GroupSignRequest) (*signerapi.GroupSignResponse, *signersigning.ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "identity runtime is nil"}
	}
	if ir.IsDecommissioned() {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: identity.ErrDecommissioned.Error()}
	}
	if !ir.IsUnlocked() {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: "signer is locked"}
	}
	if s.Deps.NewSigningService == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "signing service not configured"}
	}

	ctx, finishSignRequest := ir.BeginSigningRequest(ctx, req.RequestID)
	defer finishSignRequest()

	session := ir.SnapshotKeySession()
	result, err := s.Deps.NewSigningService(ir).SignGroupWithContext(ctx, ir.ID(), req, session)
	if err != nil {
		return nil, err
	}

	return &signerapi.GroupSignResponse{
		Signed:    result.Signed,
		Mutations: result.Mutations,
	}, nil
}

func (s Service) Plan(ir *identity.Runtime, req signerapi.GroupSignRequest) (*signerapi.GroupPlanResponse, *signersigning.ServiceError) {
	if ir == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "identity runtime is nil"}
	}
	if ir.IsDecommissioned() {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: identity.ErrDecommissioned.Error()}
	}
	if !ir.IsUnlocked() {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: "signer is locked"}
	}
	if s.Deps.PlanGroup == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "planner service not configured"}
	}
	if s.Deps.EncodeTxnHex == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "transaction encoder not configured"}
	}

	plan, err := s.Deps.PlanGroup(ir.ID(), req)
	if err != nil {
		return nil, err
	}

	txnHexes := make([]string, len(plan.AllTxns))
	for i, txn := range plan.AllTxns {
		txnHexes[i] = s.Deps.EncodeTxnHex(txn)
	}

	return &signerapi.GroupPlanResponse{
		Transactions: txnHexes,
		Mutations:    signersigning.BuildMutationReport(plan, len(req.Requests)),
	}, nil
}
