// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"fmt"
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
	// Hold leaf-family spends until the first restore from the audit log
	// has run; Reset re-arms the hold at every lock.
	fs.rotatingReleases.Reset()
	var lastRun time.Time
	wait := time.Duration(0)
	wasUnlocked := false
	var restoredGeneration uint64
	for {
		var wake <-chan struct{}
		if ir := fs.productRuntime(); ir != nil {
			wake = ir.StageWork()
		}
		forced := false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-wake:
			forced = true
		}
		ir := fs.productRuntime()
		// Read before the state: if the signer then reads unlocked, a lock
		// after this point moves the generation away from this value. Read
		// after, a lock between the two would look like the current session.
		var generation uint64
		if ir != nil {
			generation = ir.LockGeneration()
		}
		if ir == nil || !ir.IsUnlocked() {
			if wasUnlocked {
				fs.rotatingReleases.Reset()
				if ir != nil && ir.SetRotatingStatus(nil, nil, nil) {
					fs.notifyRotatingStatus(ir)
				}
			}
			wasUnlocked = false
			continue
		}
		// A lock and unlock can both fall between two passes. The generation
		// sees what polling the state can't.
		if wasUnlocked && generation != restoredGeneration {
			fs.rotatingReleases.Reset()
			wasUnlocked = false
		}
		if !forced && wasUnlocked && time.Since(lastRun) < wait {
			continue
		}
		if !wasUnlocked {
			if !fs.rebuildReleaseMemory(ctx, ir, generation) {
				continue
			}
			restoredGeneration = generation
		}
		wasUnlocked = true
		lastRun = time.Now()
		wait = fs.fillStageTables(ctx, ir)
	}
}

// rebuildReleaseMemory refills the release memory from the audit log after
// an unlock, deriving each remembered stage's addresses inside key-use
// windows. Entries the log no longer holds are simply absent. generation is the
// unlocked session the restore serves. It reports whether the restore finished:
// only then does the wait open, and otherwise the accounts stay held for another
// attempt.
func (fs *Signer) rebuildReleaseMemory(ctx context.Context, ir *productruntime.Runtime, generation uint64) bool {
	interrupted := fs.restoreReleases(ctx, ir, generation)
	if interrupted || ir.LockGeneration() != generation {
		fs.rotatingReleases.Reset()
		return false
	}
	fs.rotatingReleases.RestoredAll()
	return true
}

// restoreReleases reads the audit log into the release memory and reports whether
// a lock or cancellation interrupted it. A log that can't be read is the stated
// loss case, not an interruption.
func (fs *Signer) restoreReleases(ctx context.Context, ir *productruntime.Runtime, generation uint64) bool {
	if fs.auditLog == nil {
		return false
	}
	entries, err := signeraudit.ReadRotatingReleases(fs.auditLog.Path())
	if err != nil {
		logWarnf("rotating release memory: could not read the audit log: %v", err)
		return false
	}
	if len(entries) == 0 {
		return false
	}
	audited := make([]signersigning.AuditedRelease, 0, len(entries))
	for _, e := range entries {
		leaves := make([]signersigning.LeafRelease, 0, len(e.Leaves))
		for _, l := range e.Leaves {
			leaves = append(leaves, signersigning.LeafRelease{Tree: l.Tree, Index: l.Index, TxID: l.TxID, LastValid: l.LastValid})
		}
		audited = append(audited, signersigning.AuditedRelease{Account: e.Account, Stage: e.Stage, TxID: e.TxID, LastValid: e.LastValid, Reused: e.Reused, Leaves: leaves})
	}
	ctx, cancel := ir.LockCancelContext(ctx)
	defer cancel()
	svc := &signersigning.Service{Planner: fs.newPlannerWithAudit(nil), Console: signerConsole{}, IsUnlocked: ir.IsUnlocked, Rotating: fs.rotatingDeps(ir)}
	rebuilt, err := svc.RebuildReleaseMemory(ctx, ir.SnapshotKeySession(), generation, audited)
	if err != nil {
		logWarnf("rotating release memory: %v", err)
	}
	if rebuilt > 0 {
		logInfof("rotating release memory: %d release(s) restored from the audit log", rebuilt)
	}
	return errors.Is(err, signersigning.ErrRestoreInterrupted)
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
	fs.notifyRotatingStatus(ir)
}

func (fs *Signer) notifyRotatingStatus(ir *productruntime.Runtime) {
	if hub := fs.adminHub(); hub != nil {
		hub.NotifyStatus(ir.GetState().String(), ir.KeyCount(), ir.StatusAlerts())
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
		Session:        &session,
		Pace: func(d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(stageTablePaceFactor * d):
			}
		},
	}
	reports, cut := svc.FillStageTables(ctx, ir.SnapshotKeySession(), opts)
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
	if ctx.Err() != nil || cut {
		// Locked or shutting down mid-pass: nothing to schedule or publish.
		// A pass the lock cut is treated as not having happened, so the
		// status from the last complete pass stands until the locked worker
		// clears it.
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

// stageTableWorkerService runs the worker for the life of the daemon. The
// worker stops when shutdown begins, since its context is the Start context,
// and its stop waits for it until the shutdown deadline. A worker still
// running then (in a stage table write, which no cancellation reaches) makes
// the stop incomplete, reported as ErrStillRunning: it writes nothing to the
// audit log and holds no key material outside a key use, which
// Runtime.EndKeyUses drains before Runtime.Destroy, so teardown goes on.
func stageTableWorkerService(fs *Signer) signerstartup.LifecycleService {
	var cancel context.CancelFunc
	done := make(chan struct{})
	return signerstartup.LifecycleService{
		Name: "rotating stage table worker",
		Start: func(ctx context.Context, _ chan<- error) error {
			var workerCtx context.Context
			workerCtx, cancel = context.WithCancel(ctx)
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
				return nil
			case <-ctx.Done():
			}
			// The deadline and the worker's exit can be ready together.
			select {
			case <-done:
				return nil
			default:
				return fmt.Errorf("%w at the shutdown deadline", signerstartup.ErrStillRunning)
			}
		},
	}
}
