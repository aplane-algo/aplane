// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// AuditRotatingRecoveryLogger is implemented by audit loggers that record
// an operator's recovery request.
type AuditRotatingRecoveryLogger interface {
	LogRotatingRecovery(ctx context.Context, account, action string, grantID uint64, detail string)
}

// RecoverRotatingWithContext starts or cancels an operator recovery grant
// for a rotating account. It touches no seed and derives nothing itself:
// the stage table worker executes the grant on its next pass. Start needs
// the signer unlocked, which the REST layer checks; cancel works either way
// and is a no-op success when nothing is running.
func (s *Service) RecoverRotatingWithContext(ctx context.Context, req signerapi.RotatingRecoverRequest) (*signerapi.RotatingRecoverResponse, *ServiceError) {
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil, depErr
	}
	if deps.Recovery == nil {
		return nil, internal("rotating recovery is not configured")
	}
	session, ok := deps.recoverySession(nil)
	if !ok {
		return nil, staleSession()
	}
	// A cancel does not need the key: a locked signer holds no key files
	// and has already ended every grant, so the cancel finds nothing.
	if req.Action == signerapi.RotatingRecoverActionStart {
		snapshot := s.Planner.Snapshot()
		if _, ok := snapshot.KeyFiles[req.Account]; !ok {
			return nil, badRequest(fmt.Sprintf("no key found for account: %s", req.Account))
		}
		if !rotatingkey.IsRotatingKeyType(snapshot.KeyTypes[req.Account]) {
			return nil, badRequest(fmt.Sprintf("account %s is not a rotating account", req.Account))
		}
	}
	resp := &signerapi.RotatingRecoverResponse{Account: req.Account, Action: req.Action}
	switch req.Action {
	case signerapi.RotatingRecoverActionStart:
		grant, err := deps.Recovery.StartOperator(session, req.Account, req.Stage, req.Window, req.MaxStages, time.Duration(req.TimeoutSeconds)*time.Second)
		if err != nil {
			return nil, err
		}
		resp.GrantID = grant.ID
		s.auditRotatingRecovery(ctx, req.Account, req.Action, grant.ID, describeGrant(grant))
	case signerapi.RotatingRecoverActionCancel:
		resp.GrantID = deps.Recovery.Cancel(session, req.Account)
		detail := "nothing to cancel"
		if resp.GrantID != 0 {
			detail = fmt.Sprintf("grant %d cancelled", resp.GrantID)
		}
		s.auditRotatingRecovery(ctx, req.Account, req.Action, resp.GrantID, detail)
	}
	if st := recoveryStatus(deps.Recovery.State(req.Account)); st != nil {
		resp.Recovery = *st
	}
	return resp, nil
}

func describeGrant(g *RecoveryGrant) string {
	d := fmt.Sprintf("max_stages %d, timeout %s", g.MaxStages, g.Timeout)
	if g.Hint != nil {
		d += fmt.Sprintf(", hint stage %d, window %d", *g.Hint, g.Window)
	}
	return d
}

func (s *Service) auditRotatingRecovery(ctx context.Context, account, action string, grantID uint64, detail string) {
	if logger, ok := s.AuditLog.(AuditRotatingRecoveryLogger); ok && logger != nil {
		logger.LogRotatingRecovery(ctx, account, action, grantID, detail)
	}
}
