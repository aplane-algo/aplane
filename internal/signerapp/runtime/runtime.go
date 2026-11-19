// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

import (
	"sync"
)

// SignerState is the current lock state of the signer runtime.
type SignerState int

const (
	SignerStateLocked SignerState = iota
	SignerStateUnlocked
	SignerStateRecovery
)

const MaintenanceInProgressMessage = "store maintenance in progress"

const LockedDuringUnlockMessage = "signer locked during unlock"

func (s SignerState) String() string {
	switch s {
	case SignerStateLocked:
		return "locked"
	case SignerStateUnlocked:
		return "unlocked"
	case SignerStateRecovery:
		return "recovery"
	default:
		return "unknown"
	}
}

// Runtime owns signer lock state.
type Runtime struct {
	state SignerState
	// lockGen increments on every Lock, on every maintenance fence and its
	// end without republication, and when an unlock attempt loses to a lock
	// (lockForCleanupLocked). TryUnlock and maintenance completion re-check it
	// before publishing unlocked state, so a racing lock wins instead of
	// leaving the runtime reporting unlocked over a destroyed key session.
	lockGen uint64
	// session identifies the unlocked session: it advances on every change
	// to lockGen and on an entry into recovery from the unlocked state. It is
	// kept apart from lockGen because recovery destroys nothing: an unlock
	// that raced an entry into recovery has not lost to a lock, and must not
	// run the lock's cleanup.
	session uint64
	stateMu sync.RWMutex

	onLock func()
	// cleanups counts lock cleanups (onLock calls) that have been decided but
	// have not returned; cleanupDone is open while there is one. An unlock
	// waits for them, so it never publishes a session a cleanup is still
	// about to destroy.
	cleanups    int
	cleanupDone chan struct{}

	nextMaintenanceID   uint64
	activeMaintenanceID uint64
}

// MaintenanceToken identifies one temporary transition from active runtime
// state to locked state. Its fields are deliberately private so only the
// runtime that issued it can decide whether a later publication is still
// current.
type MaintenanceToken struct {
	id      uint64
	lockGen uint64
	// fromUnlocked records that the runtime was unlocked when the
	// maintenance began; only then may its end publish unlocked state.
	fromUnlocked bool
}

// New creates a runtime owner initialized in the locked state.
func New() *Runtime {
	return &Runtime{
		state: SignerStateLocked,
	}
}

// SetOnLock installs the callback invoked after a successful transition to locked.
func (r *Runtime) SetOnLock(fn func()) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	r.onLock = fn
}

// LockGeneration returns the session generation: a counter that advances,
// under the state mutex, on every Lock and BeginMaintenance transition, on a
// maintenance that ends without republishing, on an unlock attempt that
// loses to a lock, and on every entry into recovery from the unlocked state
// (SetRecovery, TryRecovery). Two unlocked sessions never share a generation, and a
// session ends whenever the signer leaves the unlocked state, so per-session
// state can be keyed by it and a transition that was observed late cannot be
// mistaken for the current one.
func (r *Runtime) LockGeneration() uint64 {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.session
}

// WhileGeneration runs fn if the signer is unlocked in the session generation
// names, and reports whether it ran. It holds the state lock for reading, so
// no Lock or BeginMaintenance transition falls between the check and fn: what
// fn publishes was published in that session. fn must not call back into the
// Runtime.
func (r *Runtime) WhileGeneration(generation uint64, fn func()) bool {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	if r.state != SignerStateUnlocked || r.session != generation {
		return false
	}
	fn()
	return true
}

// GetState returns the current signer state.
func (r *Runtime) GetState() SignerState {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.state
}

// IsUnlocked reports whether the signer is currently unlocked.
func (r *Runtime) IsUnlocked() bool {
	return r.GetState() == SignerStateUnlocked
}

// SetUnlocked marks the signer as unlocked without performing side effects.
func (r *Runtime) SetUnlocked() {
	r.stateMu.Lock()
	if r.activeMaintenanceID == 0 {
		r.state = SignerStateUnlocked
	}
	r.stateMu.Unlock()
}

// PromoteRecoveryToUnlocked transitions recovery -> unlocked atomically,
// honoring the lock fence: a Lock that raced the caller's recovery-exit
// rescan has already destroyed the key session and set the state to locked,
// so the promotion is refused rather than reporting unlocked over a
// destroyed session. This is the only valid way to leave recovery upward;
// SetUnlocked bypasses the fence and must not be used from recovery.
func (r *Runtime) PromoteRecoveryToUnlocked() bool {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.state != SignerStateRecovery {
		return false
	}
	r.state = SignerStateUnlocked
	return true
}

// SetRecovery marks the runtime keyring-available for explicit recovery
// administration without permitting signing. Leaving the unlocked state this
// way ends the unlocked session as a lock does: the session generation
// advances, so work that began in that session finds it over even if the
// signer is unlocked again by the time it looks. Nothing is cleared, because
// recovery administration needs the keyring; the on-lock callback does not
// run.
//
// A locked signer stays locked. Its keyring is gone, so it has no recovery
// to administer, and it signs nothing already; the unlock that follows
// reconciles the store and enters recovery itself if the store needs it. A
// store mutation a lock overtook calls this after the lock, and must not
// turn the operator's lock into recovery.
func (r *Runtime) SetRecovery() {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.activeMaintenanceID == 0 && r.state != SignerStateLocked {
		r.enterRecoveryLocked()
	}
}

// enterRecoveryLocked moves the state to recovery and, when that leaves the
// unlocked state, ends the session. The caller holds stateMu for writing.
func (r *Runtime) enterRecoveryLocked() {
	if r.state == SignerStateUnlocked {
		r.session++
	}
	r.state = SignerStateRecovery
}

// IsRecovery reports whether signing is blocked pending explicit activation
// reconciliation.
func (r *Runtime) IsRecovery() bool {
	return r.GetState() == SignerStateRecovery
}

// beginCleanupLocked records that an on-lock cleanup is about to run. The
// caller holds stateMu for writing, in the critical section that decided the
// cleanup, and then calls runCleanup after releasing it.
func (r *Runtime) beginCleanupLocked() {
	if r.cleanups == 0 {
		r.cleanupDone = make(chan struct{})
	}
	r.cleanups++
}

// runCleanup runs the on-lock callback for a cleanup beginCleanupLocked
// recorded, and releases the unlocks waiting for it when it returns.
func (r *Runtime) runCleanup(onLock func()) {
	defer func() {
		r.stateMu.Lock()
		r.cleanups--
		if r.cleanups == 0 {
			close(r.cleanupDone)
			r.cleanupDone = nil
		}
		r.stateMu.Unlock()
	}()
	if onLock != nil {
		onLock()
	}
}

// lockForCleanupLocked locks the runtime as Lock does, so that a cleanup can
// clear keys that were loaded outside a published session: the state locks,
// lockGen and the session move, and the cleanup is counted. Two callers need
// it. An unlock or recovery attempt that a lock overtook may have loaded
// keys after that lock's cleanup ran, and another attempt may since have
// published a session those keys now serve, or may publish one before this
// cleanup runs; moving lockGen ends the one and makes the other lose too. A
// maintenance that ends without republishing may have reloaded keys, which
// no later Lock would clear, since the runtime is already locked. Clearing
// can then never leave the runtime reading unlocked, or in recovery, with
// nothing behind it. The caller holds stateMu for writing and runs the
// returned callback with runCleanup after releasing it.
func (r *Runtime) lockForCleanupLocked() func() {
	r.state = SignerStateLocked
	r.lockGen++
	r.session++
	r.beginCleanupLocked()
	return r.onLock
}

// awaitCleanups waits until no on-lock cleanup is in progress and returns
// holding stateMu, for writing if write is set and for reading otherwise. A
// cleanup that begins after it returns moves lockGen first, in a critical
// section the caller's hold excludes.
func (r *Runtime) awaitCleanups(write bool) {
	for {
		if write {
			r.stateMu.Lock()
		} else {
			r.stateMu.RLock()
		}
		done := r.cleanupDone
		if done == nil {
			return
		}
		if write {
			r.stateMu.Unlock()
		} else {
			r.stateMu.RUnlock()
		}
		<-done
	}
}

// Lock transitions the runtime to locked and invokes the configured lock
// callback once. It reports whether this call performed an unlocked->locked
// transition.
func (r *Runtime) Lock() bool {
	r.stateMu.Lock()
	wasActive := r.state == SignerStateUnlocked || r.state == SignerStateRecovery
	r.state = SignerStateLocked
	r.lockGen++
	r.session++
	onLock := r.onLock
	if wasActive {
		r.beginCleanupLocked()
	}
	r.stateMu.Unlock()

	if !wasActive {
		return false
	}

	r.runCleanup(onLock)
	return true
}

// BeginMaintenance clears published signing state through the normal on-lock
// callback without emitting an external lock decision. FinishMaintenance may
// restore unlocked state only if no later Lock changed lockGen.
func (r *Runtime) BeginMaintenance() MaintenanceToken {
	r.stateMu.Lock()
	fromUnlocked := r.state == SignerStateUnlocked
	r.state = SignerStateLocked
	r.lockGen++
	r.session++
	r.nextMaintenanceID++
	if r.nextMaintenanceID == 0 {
		r.nextMaintenanceID++
	}
	r.activeMaintenanceID = r.nextMaintenanceID
	token := MaintenanceToken{
		id:           r.activeMaintenanceID,
		lockGen:      r.lockGen,
		fromUnlocked: fromUnlocked,
	}
	onLock := r.onLock
	r.beginCleanupLocked()
	r.stateMu.Unlock()

	r.runCleanup(onLock)
	return token
}

// FinishMaintenance closes the maintenance fence. It restores unlocked state
// only when the caller requests publication, the runtime was unlocked when
// the maintenance began, and no later Lock changed lockGen. Otherwise the
// runtime ends locked, and the keys the maintenance may have reloaded are
// cleared by a cleanup of its own (lockForCleanupLocked): the runtime is
// already locked, so no later Lock would clear them. A lock that landed
// before the maintenance began, after its caller checked the state, stays in
// force. It waits for a cleanup an earlier Lock left running, as an unlock
// does.
func (r *Runtime) FinishMaintenance(
	token MaintenanceToken,
	republish bool,
) bool {
	r.awaitCleanups(true)
	if token.id == 0 || r.activeMaintenanceID != token.id {
		r.stateMu.Unlock()
		return false
	}
	r.activeMaintenanceID = 0
	if republish &&
		token.fromUnlocked &&
		r.lockGen == token.lockGen &&
		r.state == SignerStateLocked {
		r.state = SignerStateUnlocked
		r.stateMu.Unlock()
		return true
	}
	onLock := r.lockForCleanupLocked()
	r.stateMu.Unlock()
	r.runCleanup(onLock)
	return false
}

// TryRecovery runs the keyring unlock function and enters recovery state
// unless a concurrent lock wins. Entered from the unlocked state (an unlock
// request on a signer already unlocked, whose store then fails validation),
// it ends the session as SetRecovery does. Like TryUnlock, it waits for a
// lock's cleanup in progress before it starts.
func (r *Runtime) TryRecovery(unlockFn func() error) (bool, string) {
	r.awaitCleanups(false)
	if r.activeMaintenanceID != 0 {
		r.stateMu.RUnlock()
		return false, MaintenanceInProgressMessage
	}
	gen := r.lockGen
	r.stateMu.RUnlock()

	if err := unlockFn(); err != nil {
		return false, err.Error()
	}

	r.stateMu.Lock()
	if r.lockGen != gen || r.activeMaintenanceID != 0 {
		onLock := r.lockForCleanupLocked()
		r.stateMu.Unlock()
		r.runCleanup(onLock)
		return false, LockedDuringUnlockMessage
	}
	r.enterRecoveryLocked()
	r.stateMu.Unlock()
	return true, ""
}

// TryUnlock runs the supplied unlock function and, on success, transitions to
// unlocked - unless a Lock call raced the unlock function, in which case the
// lock wins: the attempt locks the runtime (lockForCleanupLocked), the lock
// callback runs again to destroy whatever the unlock function loaded, and the
// unlock reports failure.
//
// It first waits for any lock cleanup in progress. A Lock moves lockGen and
// then runs its cleanup outside the state mutex; an unlock that read lockGen
// in between would pass the fence above and publish a session that cleanup
// was still about to destroy.
func (r *Runtime) TryUnlock(unlockFn func() (int, error), onUnlocked func()) (bool, int, string) {
	r.awaitCleanups(false)
	if r.activeMaintenanceID != 0 {
		r.stateMu.RUnlock()
		return false, 0, MaintenanceInProgressMessage
	}
	gen := r.lockGen
	r.stateMu.RUnlock()

	keyCount, err := unlockFn()
	if err != nil {
		return false, 0, err.Error()
	}

	r.stateMu.Lock()
	if r.lockGen != gen || r.activeMaintenanceID != 0 {
		onLock := r.lockForCleanupLocked()
		r.stateMu.Unlock()
		r.runCleanup(onLock)
		return false, 0, LockedDuringUnlockMessage
	}
	r.state = SignerStateUnlocked
	r.stateMu.Unlock()

	if onUnlocked != nil {
		onUnlocked()
	}

	return true, keyCount, ""
}
