// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
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
		IsComponentKey:    result.IsComponentKey,
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

func (s Service) AdminSyncSentryReferences(ir *identity.Runtime, req signerapi.AdminSyncSentryReferencesRequest) (signerapi.AdminSyncSentryReferencesResponse, *svcerr.Error) {
	if ir == nil {
		return signerapi.AdminSyncSentryReferencesResponse{}, &svcerr.Error{Kind: svcerr.KindInternal, Message: "identity runtime is nil"}
	}
	discovered := make([]sentryrefs.DiscoveredRecord, 0, len(req.Candidates))
	for _, candidate := range req.Candidates {
		discovered = append(discovered, sentryrefs.DiscoveredRecord{
			EndpointAlias: candidate.EndpointAlias,
			ComponentKey:  candidate.ComponentKey,
			KeyType:       candidate.KeyType,
			PublicKeyHex:  candidate.PublicKeyHex,
			LastSeenAt:    candidate.LastSeenAt,
		})
	}
	result, err := s.Deps.KeyAdmin.SyncSentryReferences(ir, discovered)
	if err != nil {
		return signerapi.AdminSyncSentryReferencesResponse{}, sanitizeKeyAdminError(err, "sentry reference sync failed")
	}
	records := make([]signerapi.SyncedSentryReferenceInfo, 0, len(result.Records))
	for _, rec := range result.Records {
		records = append(records, signerapi.SyncedSentryReferenceInfo{
			Name:          rec.Name,
			Source:        rec.Source,
			EndpointAlias: rec.EndpointAlias,
			ComponentKey:  rec.ComponentKey,
			KeyType:       rec.KeyType,
			PublicKeyHex:  rec.PublicKeyHex,
			LastSeenAt:    rec.LastSeenAt,
			SyncedAt:      rec.SyncedAt,
		})
	}
	return signerapi.AdminSyncSentryReferencesResponse{
		Added:   result.Added,
		Updated: result.Updated,
		Removed: result.Removed,
		Count:   len(result.Records),
		Records: records,
	}, nil
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
