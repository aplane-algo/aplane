// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (s Service) SignComponents(ctx context.Context, ir *identity.Runtime, req signerapi.ComponentRequest) (*signerapi.ComponentResponse, *signersigning.ServiceError) {
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if err := req.Validate(); err != nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorBadRequest, Message: err.Error()}
	}
	if roleErr := requireComponentTargetNodeRole(ir, req.TargetKind()); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}
	if req.TargetKind() != signerapi.ComponentTargetKindSentry {
		var finish func()
		ctx, finish = ir.BeginSigningRequest(ctx, req.RequestID)
		defer finish()
	}
	return s.Deps.NewSigningService(ir).SignComponentsWithContext(ctx, req, ir.SnapshotKeySession())
}

func (s Service) Assemble(ctx context.Context, ir *identity.Runtime, req signerapi.AssemblyRequest) (*signerapi.AssemblyResponse, *signersigning.ServiceError) {
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
	result, err := s.Deps.NewSigningService(ir).AssembleWithContext(ctx, req, session)
	if err != nil {
		return nil, err
	}

	return &signerapi.AssemblyResponse{
		RequestID:   result.RequestID,
		SignedGroup: result.SignedGroup,
	}, nil
}
