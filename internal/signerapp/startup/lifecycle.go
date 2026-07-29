// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"context"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

// LifecycleService is a long-lived process service started and stopped by the
// signer runtime entrypoint.
type LifecycleService struct {
	Name  string
	Start func(ctx context.Context, errs chan<- error) error
	Stop  func(ctx context.Context) error
}

// ServerAuditLogger captures the shutdown hooks needed for audit shutdown.
type ServerAuditLogger interface {
	LogServerStop()
	Close() error
}

// LifecyclePlan describes process lifecycle ownership after startup
// configuration and identity assembly are complete.
type LifecyclePlan struct {
	Services        []LifecycleService
	Registry        *identity.Registry
	ProductRuntime  *identity.Runtime
	StartWatcher    func(*identity.Runtime)
	ShutdownTimeout time.Duration
	AuditLog        ServerAuditLogger
	Info            func(string)
	Warn            func(string)
	Error           func(string)
}

// RunLifecycle owns service start, wait, shutdown ordering, audit shutdown,
// and identity runtime destruction for the signer process.
func RunLifecycle(ctx context.Context, plan LifecyclePlan) {
	if plan.ProductRuntime != nil && plan.StartWatcher != nil && plan.ProductRuntime.IsUnlocked() {
		plan.StartWatcher(plan.ProductRuntime)
	}

	errs := make(chan error, len(plan.Services))
	started := make([]LifecycleService, 0, len(plan.Services))
	for _, svc := range plan.Services {
		if svc.Start == nil {
			continue
		}
		if err := svc.Start(ctx, errs); err != nil {
			if plan.Error != nil {
				plan.Error("failed to start " + svc.Name + ": " + err.Error())
			}
			shutdownLifecycle(started, plan)
			return
		}
		started = append(started, svc)
	}

	select {
	case <-ctx.Done():
		if plan.Info != nil {
			plan.Info("shutdown signal received, cleaning up")
		}
	case err := <-errs:
		if err != nil && plan.Error != nil {
			plan.Error("server error: " + err.Error())
		}
	}

	shutdownLifecycle(started, plan)
}

func shutdownLifecycle(started []LifecycleService, plan LifecyclePlan) {
	timeout := plan.ShutdownTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i := len(started) - 1; i >= 0; i-- {
		svc := started[i]
		if svc.Stop == nil {
			continue
		}
		if plan.Info != nil && svc.Name != "" {
			plan.Info("shutting down " + svc.Name)
		}
		if err := svc.Stop(shutdownCtx); err != nil && plan.Warn != nil {
			plan.Warn(svc.Name + " shutdown error: " + err.Error())
		}
	}

	if plan.AuditLog != nil {
		plan.AuditLog.LogServerStop()
		_ = plan.AuditLog.Close()
	}

	if plan.Registry != nil {
		if plan.Info != nil {
			plan.Info("zeroing cached keys and the keyring")
		}
		for _, rt := range plan.Registry.All() {
			rt.Destroy()
		}
	}

	if plan.Info != nil {
		plan.Info("shutdown complete")
	}
}
