// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
)

func (s Service) AdminGenerate(ctx context.Context, ir *identity.Runtime, req signerapi.AdminGenerateRequest) (int, signerapi.AdminGenerateResponse) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return 500, signerapi.AdminGenerateResponse{Error: "identity runtime is nil"}
	}
	if !ir.IsUnlocked() {
		return 403, signerapi.AdminGenerateResponse{Error: "signer is locked"}
	}

	result, err := s.Deps.KeyAdmin.GenerateKey(ctx, ir, req.KeyType, req.Parameters, s.Deps.GenerateGenericLSig)
	if err != nil {
		return mapGenerateError(err)
	}

	return 200, signerapi.AdminGenerateResponse{
		Address:           result.Address,
		ComponentKeyID:    result.ComponentKeyID,
		PublicKeyHex:      result.PublicKeyHex,
		KeyType:           result.KeyType,
		IsComponentKey:    result.IsComponentKey,
		IsSpendingAccount: result.IsSpendingAccount,
		Parameters:        result.Parameters,
	}
}

func (s Service) AdminDelete(ir *identity.Runtime, address string) (int, signerapi.AdminDeleteResponse) {
	if ir == nil {
		return 500, signerapi.AdminDeleteResponse{Error: "identity runtime is nil"}
	}
	if !ir.IsUnlocked() {
		return 403, signerapi.AdminDeleteResponse{Error: "signer is locked"}
	}

	if _, err := s.Deps.KeyAdmin.DeleteKey(ir, address); err != nil {
		return mapDeleteError(err)
	}

	return 200, signerapi.AdminDeleteResponse{Success: true}
}

func mapGenerateError(err *keyadmin.Error) (int, signerapi.AdminGenerateResponse) {
	if err == nil {
		return 200, signerapi.AdminGenerateResponse{}
	}
	switch err.Kind {
	case keyadmin.ErrorInvalidInput:
		return 400, signerapi.AdminGenerateResponse{Error: err.Message}
	case keyadmin.ErrorLocked:
		return 403, signerapi.AdminGenerateResponse{Error: err.Message}
	default:
		if err.Message != "failed to refresh signer key cache" {
			return 500, signerapi.AdminGenerateResponse{Error: "key generation failed"}
		}
		return 500, signerapi.AdminGenerateResponse{Error: err.Message}
	}
}

func mapDeleteError(err *keyadmin.Error) (int, signerapi.AdminDeleteResponse) {
	if err == nil {
		return 200, signerapi.AdminDeleteResponse{Success: true}
	}
	switch err.Kind {
	case keyadmin.ErrorInvalidInput:
		msg := err.Message
		if err.Message == "address is required" {
			msg = "address query parameter is required"
		}
		return 400, signerapi.AdminDeleteResponse{Error: msg}
	case keyadmin.ErrorLocked:
		return 403, signerapi.AdminDeleteResponse{Error: err.Message}
	case keyadmin.ErrorNotFound:
		return 404, signerapi.AdminDeleteResponse{Error: err.Message}
	default:
		return 500, signerapi.AdminDeleteResponse{Error: "key deletion failed"}
	}
}
