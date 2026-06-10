// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (s Service) SignComponent(ctx context.Context, ir *identity.Runtime, req signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, *signersigning.ServiceError) {
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
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorLocked, Message: "signer is locked"}
	}
	if roleErr := requireComponentNodeRole(ir, req.Role); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "signing service not configured"}
	}

	session := ir.SnapshotKeySession()
	result, err := s.Deps.NewSigningService(ir).SignComponentWithContext(ctx, ir.ID(), req, session)
	if err != nil {
		return nil, err
	}

	return &signerapi.ComponentSignResponse{
		RequestID:    result.RequestID,
		ComponentKey: result.ComponentKey,
		Signatures:   result.Signatures,
	}, nil
}

func (s Service) AssembleGuarded(ctx context.Context, ir *identity.Runtime, req signerapi.GuardedAssemblyRequest) (*signerapi.GuardedAssemblyResponse, *signersigning.ServiceError) {
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
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorLocked, Message: "signer is locked"}
	}
	if roleErr := requireAccountSigningRole(ir, "guarded assembly"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "signing service not configured"}
	}

	session := ir.SnapshotKeySession()
	result, err := s.Deps.NewSigningService(ir).AssembleGuardedWithContext(ctx, ir.ID(), req, session)
	if err != nil {
		return nil, err
	}

	return &signerapi.GuardedAssemblyResponse{
		RequestID:   result.RequestID,
		SignedGroup: result.SignedGroup,
	}, nil
}
