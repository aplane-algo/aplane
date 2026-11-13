// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// LifecycleService is a long-lived process service started and stopped by the
// signer runtime entrypoint. The context Start receives ends when shutdown
// begins, before any Stop runs, whatever began the shutdown.
type LifecycleService struct {
	Name  string
	Start func(ctx context.Context, errs chan<- error) error
	Stop  func(ctx context.Context) error
}

// ServerAuditLogger captures the shutdown hooks needed for audit shutdown.
type ServerAuditLogger interface {
	LogServerStop()
	LogServerStopIncomplete(reason string)
	Close() error
}

// LifecyclePlan describes process lifecycle ownership after startup
// configuration and identity assembly are complete.
type LifecyclePlan struct {
	Services       []LifecycleService
	ProductRuntime *productruntime.Runtime
	StartWatcher   func(*productruntime.Runtime)
	// ShutdownTimeout bounds the service stops together, and separately the
	// wait for key users before the keyring is zeroed. Zero means 5s.
	ShutdownTimeout time.Duration
	AuditLog        ServerAuditLogger
	Info            func(string)
	Warn            func(string)
	Error           func(string)
}

// RunLifecycle owns service start, wait, shutdown ordering, audit shutdown,
// and product runtime destruction for the signer process. It returns the
// service start failure or serve failure that ended the run, after shutting
// down, and nil when ctx ended it; the signer exits non-zero on an error.
func RunLifecycle(ctx context.Context, plan LifecyclePlan) error {
	if plan.ProductRuntime != nil && plan.StartWatcher != nil && plan.ProductRuntime.IsUnlocked() {
		plan.StartWatcher(plan.ProductRuntime)
	}

	// A service's background work tied to its Start context stops as soon as
	// shutdown begins, not at its own turn in the stop order.
	runCtx, endRun := context.WithCancel(ctx)
	defer endRun()

	errs := make(chan error, len(plan.Services))
	started := make([]LifecycleService, 0, len(plan.Services))
	for _, svc := range plan.Services {
		if svc.Start == nil {
			continue
		}
		if err := svc.Start(runCtx, errs); err != nil {
			if plan.Error != nil {
				plan.Error("failed to start " + svc.Name + ": " + err.Error())
			}
			endRun()
			shutdownLifecycle(started, plan)
			return fmt.Errorf("failed to start %s: %w", svc.Name, err)
		}
		started = append(started, svc)
	}

	var runErr error
	select {
	case <-ctx.Done():
		if plan.Info != nil {
			plan.Info("shutdown signal received, cleaning up")
		}
	case err := <-errs:
		if err != nil {
			if plan.Error != nil {
				plan.Error("server error: " + err.Error())
			}
			runErr = fmt.Errorf("server error: %w", err)
		}
	}

	endRun()
	shutdownLifecycle(started, plan)
	return runErr
}

func shutdownLifecycle(started []LifecycleService, plan LifecyclePlan) {
	timeout := plan.ShutdownTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var shutdownErrors []string
	handlersMayBeRunning := false
	for i := len(started) - 1; i >= 0; i-- {
		svc := started[i]
		if svc.Stop == nil {
			continue
		}
		if plan.Info != nil && svc.Name != "" {
			plan.Info("shutting down " + svc.Name)
		}
		if err := svc.Stop(shutdownCtx); err != nil {
			shutdownErrors = append(shutdownErrors, svc.Name+": "+err.Error())
			if errors.Is(err, context.DeadlineExceeded) {
				handlersMayBeRunning = true
			}
			if plan.Warn != nil {
				plan.Warn(svc.Name + " shutdown error: " + err.Error())
			}
		}
	}

	// A timed-out server may still have handlers using the audit logger and
	// runtime-owned key material. Do not tear either dependency down underneath
	// those handlers. The signer process returns immediately after this path, so
	// the operating system performs the final process-memory and descriptor
	// cleanup without creating an in-process use-after-destroy window.
	if handlersMayBeRunning {
		if plan.AuditLog != nil {
			plan.AuditLog.LogServerStopIncomplete(strings.Join(shutdownErrors, "; "))
		}
		if plan.Warn != nil {
			plan.Warn("service shutdown incomplete; retaining audit and runtime state until process exit")
		}
		return
	}

	// Every service has stopped, but a background key user (a stage table
	// derivation, a key export) may still hold key material. Destroy waits
	// for it with a deadline of its own, so other services' stops cannot use
	// up its wait, and zeroes the keyring either way.
	keyUseInFlight := false
	if plan.ProductRuntime != nil {
		if plan.Info != nil {
			plan.Info("zeroing cached keys and the keyring")
		}
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
		err := plan.ProductRuntime.Destroy(drainCtx)
		cancelDrain()
		if err != nil {
			keyUseInFlight = true
			shutdownErrors = append(shutdownErrors, "product runtime: "+err.Error())
			if plan.Warn != nil {
				plan.Warn("product runtime shutdown error: " + err.Error() + "; its copy is released at process exit")
			}
		}
	}

	if plan.AuditLog != nil {
		if len(shutdownErrors) == 0 {
			plan.AuditLog.LogServerStop()
		} else {
			plan.AuditLog.LogServerStopIncomplete(strings.Join(shutdownErrors, "; "))
		}
		// A key user still running may write its audit record when it ends
		// (a key export does).
		if !keyUseInFlight {
			_ = plan.AuditLog.Close()
		}
	}

	if plan.Info != nil {
		plan.Info("shutdown complete")
	}
}
