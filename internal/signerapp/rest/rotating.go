// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// RotatingSigningService is the rotating account flow. It is separate from
// SigningService so the ordinary signing contract stays unchanged.
type RotatingSigningService interface {
	PrepareRotatingWithContext(ctx context.Context, req signerapi.RotatingPrepareRequest, session *keystore.KeySession) (*signerapi.RotatingPrepareResponse, *signersigning.ServiceError)
	SignRotatingWithContext(ctx context.Context, req signerapi.RotatingSignRequest, session *keystore.KeySession) (*signerapi.RotatingSignResponse, *signersigning.ServiceError)
}

// RotatingRecoveryService starts and cancels operator stage recovery.
type RotatingRecoveryService interface {
	RecoverRotatingWithContext(ctx context.Context, req signerapi.RotatingRecoverRequest) (*signerapi.RotatingRecoverResponse, *signersigning.ServiceError)
}

// RecoverRotating starts or cancels an operator recovery grant. Starting
// one needs the signer unlocked, since the grant derives from the seed;
// cancelling does not, and finds nothing to cancel once a lock has ended
// every grant.
func (s Service) RecoverRotating(ctx context.Context, ir *productruntime.Runtime, req signerapi.RotatingRecoverRequest) (*signerapi.RotatingRecoverResponse, *signersigning.ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "product runtime is nil"}
	}
	if req.Action != signerapi.RotatingRecoverActionCancel {
		if preErr := ensureRuntimeUnlocked(ir); preErr != nil {
			return nil, preErr
		}
	}
	if roleErr := requireAccountSigningRole(ir, "rotating account recovery"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}
	svc, ok := s.Deps.NewSigningService(ir).(RotatingRecoveryService)
	if !ok {
		return nil, notConfigured("rotating recovery service")
	}
	return svc.RecoverRotatingWithContext(ctx, req)
}

func (s Service) rotatingService(ir *productruntime.Runtime) (RotatingSigningService, *signersigning.ServiceError) {
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}
	svc, ok := s.Deps.NewSigningService(ir).(RotatingSigningService)
	if !ok {
		return nil, notConfigured("rotating signing service")
	}
	return svc, nil
}

// PrepareRotating prepares one rotating account spend. Like /plan it needs no
// approval and stores nothing.
func (s Service) PrepareRotating(ctx context.Context, ir *productruntime.Runtime, req signerapi.RotatingPrepareRequest) (*signerapi.RotatingPrepareResponse, *signersigning.ServiceError) {
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "preparing rotating account signing"); roleErr != nil {
		return nil, roleErr
	}
	svc, err := s.rotatingService(ir)
	if err != nil {
		return nil, err
	}
	return svc.PrepareRotatingWithContext(ctx, req, ir.SnapshotKeySession())
}

// SignRotating signs a prepared rotating group after approval.
func (s Service) SignRotating(ctx context.Context, ir *productruntime.Runtime, req signerapi.RotatingSignRequest) (*signerapi.RotatingSignResponse, *signersigning.ServiceError) {
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "rotating account signing"); roleErr != nil {
		return nil, roleErr
	}
	svc, err := s.rotatingService(ir)
	if err != nil {
		return nil, err
	}
	ctx, finishSignRequest := ir.BeginSigningRequest(ctx, req.RequestID)
	defer finishSignRequest()
	return svc.SignRotatingWithContext(ctx, req, ir.SnapshotKeySession())
}
