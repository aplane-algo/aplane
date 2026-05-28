// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"errors"
	"time"

	"github.com/aplane-algo/aplane/internal/engine"
)

func (r *REPLState) startSignerStatusPolling(onCacheChanged func()) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	interval := r.Config.SignerStatusPollIntervalDuration()
	if interval <= 0 {
		return cancel
	}
	go r.runSignerStatusPoller(ctx, interval, onCacheChanged)
	return cancel
}

func (r *REPLState) runSignerStatusPoller(ctx context.Context, interval time.Duration, onCacheChanged func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.pollSignerStatus(ctx, interval, onCacheChanged)
		}
	}
}

func (r *REPLState) pollSignerStatus(ctx context.Context, interval time.Duration, onCacheChanged func()) {
	if r == nil || r.App == nil || !r.app().IsConnected() {
		return
	}

	timeout := interval / 2
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r.runtimeMu.Lock()
	defer r.runtimeMu.Unlock()

	result, err := r.app().SyncSignerStatus(pollCtx)
	if err != nil {
		if errors.Is(err, engine.ErrNotConnected) {
			return
		}
		return
	}
	if result != nil && (result.CacheRefreshed || result.CacheCleared) && onCacheChanged != nil {
		onCacheChanged()
	}
}
