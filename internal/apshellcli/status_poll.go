// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"time"
)

func (r *REPLState) startSignerStatusPolling() context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	interval := r.app().Config.SignerStatusPollIntervalDuration()
	if interval <= 0 {
		return cancel
	}
	go r.runSignerStatusPoller(ctx, interval)
	return cancel
}

func (r *REPLState) runSignerStatusPoller(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.pollSignerStatus(ctx, interval)
		}
	}
}

func (r *REPLState) pollSignerStatus(ctx context.Context, interval time.Duration) {
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

	// A failed poll changes nothing, and the next one tries again. A cache
	// the poll refreshed reaches completion at the next Tab, which builds its
	// completer from the caches as they are then.
	_, _ = r.app().SyncSignerStatus(pollCtx)
}
