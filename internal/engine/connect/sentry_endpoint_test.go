// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"errors"
	"testing"
)

func TestSentryTunnelLifetimeDetachesAfterSetup(t *testing.T) {
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	lifetimeCtx, cancelLifetime, detach := newSentryTunnelLifetime(setupCtx)
	defer cancelLifetime()

	if err := detach(); err != nil {
		t.Fatalf("detach() error = %v", err)
	}
	cancelSetup()
	select {
	case <-lifetimeCtx.Done():
		t.Fatalf("detached tunnel canceled with setup context: %v", lifetimeCtx.Err())
	default:
	}

	cancelLifetime()
	if !errors.Is(lifetimeCtx.Err(), context.Canceled) {
		t.Fatalf("lifetime context error = %v, want canceled", lifetimeCtx.Err())
	}
}

func TestSentryTunnelLifetimeHonorsSetupCancellation(t *testing.T) {
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	_, cancelLifetime, detach := newSentryTunnelLifetime(setupCtx)
	defer cancelLifetime()
	cancelSetup()

	if err := detach(); !errors.Is(err, context.Canceled) {
		t.Fatalf("detach() error = %v, want context canceled", err)
	}
}
