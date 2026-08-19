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
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "account signing"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}

	ctx, finishSignRequest := ir.BeginSigningRequest(ctx, req.RequestID)
	defer finishSignRequest()

	session := ir.SnapshotKeySession()
	result, err := s.Deps.NewSigningService(ir).SignGroupWithContext(ctx, req, session)
	if err != nil {
		return nil, err
	}

	return &signerapi.GroupSignResponse{
		Signed:    result.Signed,
		Mutations: result.Mutations,
	}, nil
}

func (s Service) PrepareBoundedAdmin(ctx context.Context, ir *identity.Runtime, req signerapi.BoundedAdminRequest) (*signerapi.BoundedAdminPartialResponse, *signersigning.ServiceError) {
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "preparing bounded admin operation"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}

	ctx, finishSignRequest := ir.BeginSigningRequest(ctx, req.RequestID)
	defer finishSignRequest()

	result, err := s.Deps.NewSigningService(ir).PrepareBoundedAdminWithContext(ctx, req, ir.SnapshotKeySession())
	if err != nil {
		return nil, err
	}
	return &signerapi.BoundedAdminPartialResponse{
		Schema:        signerapi.BoundedAdminPartialSchemaV1,
		Operation:     result.Operation,
		Transactions:  result.Transactions,
		PartialSigned: result.PartialSigned,
		TargetIndex:   result.TargetIndex,
		Authorization: result.Authorization,
		Mutations:     result.Mutations,
	}, nil
}

func (s Service) Plan(ir *identity.Runtime, req signerapi.GroupSignRequest) (*signerapi.GroupPlanResponse, *signersigning.ServiceError) {
	// Plan takes no context: it never signs, so there is no request to
	// register or cancel; only the runtime preconditions apply.
	if _, preErr := ensureSignable(context.Background(), ir); preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "planning account signing"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.PlanGroup == nil {
		return nil, notConfigured("planner service")
	}
	if s.Deps.EncodeTxnHex == nil {
		return nil, notConfigured("transaction encoder")
	}

	plan, err := s.Deps.PlanGroup(req)
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
