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
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireComponentNodeRole(ir, req.Role); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
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
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "guarded assembly"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
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
