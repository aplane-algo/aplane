// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
)

func (s Service) AdminGenerate(ctx context.Context, ir *productruntime.Runtime, req signerapi.AdminGenerateRequest) (signerapi.AdminGenerateResponse, *svcerr.Error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return signerapi.AdminGenerateResponse{}, err
	}

	result, err := s.Deps.KeyAdmin.GenerateKey(ctx, req.KeyType, req.Parameters, s.Deps.GenerateGenericLSig)
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

func (s Service) AdminDelete(ir *productruntime.Runtime, address string) (signerapi.AdminDeleteResponse, *svcerr.Error) {
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return signerapi.AdminDeleteResponse{}, err
	}

	if _, err := s.Deps.KeyAdmin.DeleteKey(address); err != nil {
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
