// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
)

func (s Service) AdminGenerate(ctx context.Context, ir *identity.Runtime, req signerapi.AdminGenerateRequest) (signerapi.AdminGenerateResponse, *svcerr.Error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return signerapi.AdminGenerateResponse{}, &svcerr.Error{Kind: svcerr.KindInternal, Message: "identity runtime is nil"}
	}
	if !ir.IsUnlocked() {
		return signerapi.AdminGenerateResponse{}, &svcerr.Error{Kind: svcerr.KindLocked, Message: "signer is locked"}
	}

	result, err := s.Deps.KeyAdmin.GenerateKey(ctx, ir, req.KeyType, req.Parameters, s.Deps.GenerateGenericLSig)
	if err != nil {
		return signerapi.AdminGenerateResponse{}, sanitizeKeyAdminError(err, "key generation failed")
	}

	return signerapi.AdminGenerateResponse{
		Address:           result.Address,
		PublicKeyHex:      result.PublicKeyHex,
		KeyType:           result.KeyType,
		IsWitnessKey:      result.IsWitnessKey,
		IsSpendingAccount: result.IsSpendingAccount,
		Parameters:        result.Parameters,
	}, nil
}

func (s Service) AdminDelete(ir *identity.Runtime, address string) (signerapi.AdminDeleteResponse, *svcerr.Error) {
	if ir == nil {
		return signerapi.AdminDeleteResponse{}, &svcerr.Error{Kind: svcerr.KindInternal, Message: "identity runtime is nil"}
	}
	if !ir.IsUnlocked() {
		return signerapi.AdminDeleteResponse{}, &svcerr.Error{Kind: svcerr.KindLocked, Message: "signer is locked"}
	}

	if _, err := s.Deps.KeyAdmin.DeleteKey(ir, address); err != nil {
		if err.Kind == svcerr.KindBadRequest && err.Message == "address is required" {
			return signerapi.AdminDeleteResponse{}, &svcerr.Error{Kind: svcerr.KindBadRequest, Message: "address query parameter is required"}
		}
		return signerapi.AdminDeleteResponse{}, sanitizeKeyAdminError(err, "key deletion failed")
	}

	return signerapi.AdminDeleteResponse{Success: true}, nil
}

// sanitizeKeyAdminError passes kinded errors through to the wire and hides
// internal failure detail behind a stable per-operation message.
func sanitizeKeyAdminError(err *svcerr.Error, internalMessage string) *svcerr.Error {
	if err == nil {
		return nil
	}
	if err.Kind == svcerr.KindInternal {
		return &svcerr.Error{Kind: svcerr.KindInternal, Message: internalMessage}
	}
	return err
}
