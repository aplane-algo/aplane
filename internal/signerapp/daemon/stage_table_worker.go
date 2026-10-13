// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

const (
	// stageTableTick is how often the worker looks for an unlock.
	stageTableTick = 5 * time.Second

	// stageTableIdleInterval is how often an unlocked signer revisits
	// rotating accounts whose tables are already resolved and filled.
	stageTableIdleInterval = 30 * time.Second

	// stageTableBusyInterval is the pause between passes while some account
	// is still unresolved, so its scan keeps moving without spinning.
	stageTableBusyInterval = time.Second

	// stageTablePaceFactor is how long the worker sleeps after each
	// derivation, as a multiple of the derivation's own duration: 3 holds
	// the worker to about a quarter of one core.
	stageTablePaceFactor = 3
)

// runStageTableWorker keeps every rotating account's stage address table
// filled: right after each unlock, then periodically while unlocked. An
// account whose authorizer is already in its table is extended to the
// configured horizon; an account whose authorizer is not yet known is
// scanned on, one batch per pass, without a ceiling.
func (fs *Signer) runStageTableWorker(ctx context.Context) {
	ticker := time.NewTicker(stageTableTick)
	defer ticker.Stop()
	var lastRun time.Time
	wait := time.Duration(0)
	wasUnlocked := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		ir := fs.productRuntime()
		if ir == nil || !ir.IsUnlocked() {
			wasUnlocked = false
			continue
		}
		if wasUnlocked && time.Since(lastRun) < wait {
			continue
		}
		wasUnlocked = true
		lastRun = time.Now()
		wait = fs.fillStageTables(ctx, ir)
	}
}

// fillStageTables runs one pass and returns how long to wait before the next.
// The pass registers as a key user, so locking the signer cancels it within
// one derivation and waits for it to release the seed before the session is
// cleared.
func (fs *Signer) fillStageTables(ctx context.Context, ir *productruntime.Runtime) time.Duration {
	ctx, release := ir.KeyUseContext(ctx)
	defer release()
	svc := &signersigning.Service{
		Planner:  fs.newPlannerWithAudit(nil),
		Console:  signerConsole{},
		Rotating: fs.rotatingDeps(ir),
	}
	opts := signersigning.StageFillOptions{
		Horizon:        fs.ConfigSnapshot().Rotating.StageHorizon,
		Batch:          fs.stageFillBatch,
		MaxDerivations: fs.stageFillMaxDeriv,
		Parallel:       1,
		Pace: func(d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(stageTablePaceFactor * d):
			}
		},
	}
	reports := svc.FillStageTables(ctx, ir.SnapshotKeySession(), opts)
	wait := stageTableIdleInterval
	for _, r := range reports {
		if r.Discarded != nil {
			logWarnf("rotating account %s: %v; rebuilding its stage table from the seed", r.Account, r.Discarded)
		}
		if r.Err != nil {
			logWarnf("rotating account %s: stage table: %v", r.Account, r.Err)
			continue
		}
		if !r.Resolved {
			logInfof("rotating account %s: stage not yet found, %d stages scanned", r.Account, r.Scanned)
		}
		if r.Pending {
			wait = stageTableBusyInterval
		}
	}
	if ctx.Err() != nil {
		// Locked or shutting down mid-pass: nothing to schedule.
		return stageTableIdleInterval
	}
	return wait
}

// stageTableWorkerService runs the worker for the life of the daemon.
func stageTableWorkerService(fs *Signer) signerstartup.LifecycleService {
	var cancel context.CancelFunc
	done := make(chan struct{})
	return signerstartup.LifecycleService{
		Name: "rotating stage table worker",
		Start: func(ctx context.Context, _ chan<- error) error {
			var workerCtx context.Context
			workerCtx, cancel = context.WithCancel(context.Background())
			go func() {
				defer close(done)
				fs.runStageTableWorker(workerCtx)
			}()
			return nil
		},
		Stop: func(ctx context.Context) error {
			if cancel == nil {
				return nil
			}
			cancel()
			select {
			case <-done:
			case <-ctx.Done():
			}
			return nil
		},
	}
}
