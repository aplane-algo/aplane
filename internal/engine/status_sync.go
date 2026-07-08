// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

// SignerStatusSyncResult describes the effect of comparing /status with
// apshell's local signer cache.
type SignerStatusSyncResult struct {
	Status          *signerapi.StatusResponse
	FirstSync       bool
	RevisionChanged bool
	CacheRefreshed  bool
	CacheCleared    bool
}

func (e *Engine) SyncSignerStatus(ctx context.Context) (*SignerStatusSyncResult, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}

	status, err := e.GetSignerStatusWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signer status: %w", err)
	}

	e.signerStatusMu.Lock()
	defer e.signerStatusMu.Unlock()

	firstSync := !e.signerStatusRevisionSeen
	revisionChanged := !firstSync && status.KeysetRevision != e.signerStatusKeysetRevSeen
	result := &SignerStatusSyncResult{
		Status:          status,
		FirstSync:       firstSync,
		RevisionChanged: revisionChanged,
	}

	if !status.ReadyForSigning {
		if firstSync || revisionChanged || e.signerCacheCount() > 0 || !e.signerCacheIsLocked() {
			e.resetSignerCache(true)
			result.CacheCleared = true
		}
		e.signerStatusRevisionSeen = true
		e.signerStatusKeysetRevSeen = status.KeysetRevision
		return result, nil
	}

	needsRefresh := revisionChanged || e.signerCacheIsLocked() || e.signerCacheCount() != status.KeyCount
	if needsRefresh {
		if _, err := e.RefreshKeys(ctx); err != nil {
			return result, err
		}
		result.CacheRefreshed = true
	}

	e.signerStatusRevisionSeen = true
	e.signerStatusKeysetRevSeen = status.KeysetRevision
	return result, nil
}

func (e *Core) resetSignerStatusRevision() {
	e.signerStatusMu.Lock()
	e.signerStatusRevisionSeen = false
	e.signerStatusKeysetRevSeen = 0
	e.signerStatusMu.Unlock()
}
