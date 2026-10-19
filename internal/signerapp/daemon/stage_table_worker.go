// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"slices"
	"time"

	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
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
// filled and its status current: right after each unlock, then periodically
// while unlocked. An account whose authorizer is already in its table is
// extended to the configured horizon. An account whose authorizer is not in
// its table is classified first (a credential this signer holds means the
// account was rekeyed away, and nothing is derived); an authorizer that is
// unknown is searched for under a recovery grant, one batch per pass, bounded
// by the per-unlock allowance or by the operator's budget, never without a
// ceiling. Each pass also compares every account's authorizer with the
// release memory and publishes the resulting warnings, notes and per-account
// status. At unlock the release memory is rebuilt from the audit log and
// at lock it is forgotten with everything else; the recovery allowances
// are keyed by the lock generation and begin afresh with each unlock.
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
			if wasUnlocked {
				fs.rotatingReleases.Reset()
				if ir != nil && ir.SetRotatingStatus(nil, nil, nil) {
					fs.notifyRotatingStatus(ir, nil)
				}
			}
			wasUnlocked = false
			continue
		}
		if wasUnlocked && time.Since(lastRun) < wait {
			continue
		}
		if !wasUnlocked {
			fs.rebuildReleaseMemory(ctx, ir)
		}
		wasUnlocked = true
		lastRun = time.Now()
		wait = fs.fillStageTables(ctx, ir)
	}
}

// rebuildReleaseMemory refills the release memory from the audit log after
// an unlock, deriving each remembered stage's addresses inside key-use
// windows. Entries the log no longer holds are simply absent.
func (fs *Signer) rebuildReleaseMemory(ctx context.Context, ir *productruntime.Runtime) {
	if fs.auditLog == nil {
		return
	}
	entries, err := signeraudit.ReadRotatingReleases(fs.auditLog.Path())
	if err != nil {
		logWarnf("rotating release memory: could not read the audit log: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	audited := make([]signersigning.AuditedRelease, 0, len(entries))
	for _, e := range entries {
		audited = append(audited, signersigning.AuditedRelease{Account: e.Account, Stage: e.Stage, TxID: e.TxID, LastValid: e.LastValid, Reused: e.Reused})
	}
	ctx, cancel := ir.LockCancelContext(ctx)
	defer cancel()
	svc := &signersigning.Service{Planner: fs.newPlannerWithAudit(nil), Console: signerConsole{}, Rotating: fs.rotatingDeps(ir)}
	rebuilt, err := svc.RebuildReleaseMemory(ctx, ir.SnapshotKeySession(), audited, signersigning.StageFillOptions{KeyUse: ir.KeyUseContext})
	if err != nil {
		logWarnf("rotating release memory: %v", err)
	}
	if rebuilt > 0 {
		logInfof("rotating release memory: %d release(s) restored from the audit log", rebuilt)
	}
}

// publishRotatingStatus records a pass's warnings, notes and per-account
// status on the runtime, logs what changed, and tells a connected apadmin.
func (fs *Signer) publishRotatingStatus(ir *productruntime.Runtime, svc *signersigning.Service, reports []signersigning.StageTableReport) {
	warnings, notes := svc.RotatingStatus(reports)
	previous := ir.RotatingAlerts()
	if !ir.SetRotatingStatus(warnings, notes, svc.RotatingAccountStatuses(reports)) {
		return
	}
	for _, w := range warnings {
		if !slices.Contains(previous, w) {
			logWarnf("ROTATING ACCOUNT ALERT: %s", w)
		}
	}
	for _, w := range previous {
		if !slices.Contains(warnings, w) {
			logInfof("rotating account alert cleared: %s", w)
		}
	}
	fs.notifyRotatingStatus(ir, warnings)
}

func (fs *Signer) notifyRotatingStatus(ir *productruntime.Runtime, warnings []string) {
	if hub := fs.adminHub(); hub != nil {
		hub.NotifyStatus(ir.GetState().String(), ir.KeyCount(), warnings)
	}
}

// fillStageTables runs one pass and returns how long to wait before the next.
// The whole pass runs under a context that locking cancels, so a chain read
// or a pacing sleep ends at lock and the worker is free for the next unlock.
// Separately, every window in which the pass holds a seed is registered as a
// key use, so the lock also waits for the seed to be released before the
// session is cleared; the chain read, the table write and the pacing sleep
// happen with no key material in memory.
func (fs *Signer) fillStageTables(ctx context.Context, ir *productruntime.Runtime) time.Duration {
	session, ctx, cancel, ok := passSession(ctx, ir.LockGeneration, ir.LockCancelContext)
	defer cancel()
	if !ok {
		return stageTableIdleInterval
	}
	cfg := fs.ConfigSnapshot().Rotating
	fs.rotatingRecovery.Configure(cfg.RecoveryMaxStages, cfg.RecoveryTimeout)
	svc := &signersigning.Service{
		Planner:  fs.newPlannerWithAudit(nil),
		Console:  signerConsole{},
		Rotating: fs.rotatingDeps(ir),
	}
	opts := signersigning.StageFillOptions{
		Horizon:        cfg.StageHorizon,
		Batch:          fs.stageFillBatch,
		MaxDerivations: fs.stageFillMaxDeriv,
		Parallel:       1,
		KeyUse:         ir.KeyUseContext,
		Session:        &session,
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
		if r.Pending {
			wait = stageTableBusyInterval
		}
	}
	if ctx.Err() != nil {
		// Locked or shutting down mid-pass: nothing to schedule or publish.
		return stageTableIdleInterval
	}
	fs.publishRotatingStatus(ir, svc, reports)
	return wait
}

// passSession captures a pass's session together with the context a lock
// cancels. The session is read first; a lock between that read and the
// context's creation leaves the context born cancelled, and a lock and
// unlock between them leave a session the recovery memory refuses on
// entry, since it validates every caller against the runtime's live
// generation. Either way the pass never acts in a session other than the
// one that owns its cancellation.
func passSession(parent context.Context, generation func() uint64, cancelContext func(context.Context) (context.Context, context.CancelFunc)) (uint64, context.Context, context.CancelFunc, bool) {
	session := generation()
	ctx, cancel := cancelContext(parent)
	if ctx.Err() != nil {
		return 0, ctx, cancel, false
	}
	return session, ctx, cancel, true
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
