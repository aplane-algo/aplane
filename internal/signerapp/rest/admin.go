// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func (s Service) AdminGenerate(ctx context.Context, ir *productruntime.Runtime, req signerapi.AdminGenerateRequest) (signerapi.AdminGenerateResponse, *svcerr.Error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return signerapi.AdminGenerateResponse{}, err
	}

	result, err := s.Deps.KeyAdmin.GenerateKey(ctx, req.KeyType, req.Parameters)
	if err != nil {
		return signerapi.AdminGenerateResponse{}, sanitizeKeyAdminError(err, "key generation failed")
	}

	return signerapi.AdminGenerateResponse{
		Address:      result.Address,
		PublicKeyHex: result.PublicKeyHex,
		KeyType:      result.KeyType,
		IsWitnessKey: result.IsWitnessKey,
		Parameters:   result.Parameters,
		Warnings:     result.Warnings,
	}, nil
}

func (s Service) AdminDelete(ctx context.Context, ir *productruntime.Runtime, address string) *svcerr.Error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return err
	}

	if _, err := s.Deps.KeyAdmin.DeleteKey(ctx, address); err != nil {
		if err.Kind == svcerr.KindBadRequest && err.Message == "address is required" {
			return &svcerr.Error{Kind: svcerr.KindBadRequest, Message: "address query parameter is required"}
		}
		return sanitizeKeyAdminError(err, "key deletion failed")
	}
	return nil
}

// sanitizeKeyAdminError passes kinded errors through to the wire and hides
// internal failure detail behind a stable per-operation message. A change
// whose reload entered recovery answers as the HTTP API's cache_refresh,
// without the store detail the admin answer names.
func sanitizeKeyAdminError(err *svcerr.Error, internalMessage string) *svcerr.Error {
	switch {
	case err == nil:
		return nil
	case err.Kind == svcerr.KindInternal:
		return &svcerr.Error{Kind: svcerr.KindInternal, Message: internalMessage}
	case err.Kind == svcerr.KindRecoveryBlocked:
		return &svcerr.Error{Kind: svcerr.KindCacheRefresh, Message: "failed to refresh signer key cache: the signer entered recovery"}
	default:
		return err
	}
}
