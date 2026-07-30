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
	// lockGen increments on every Lock and maintenance fence. TryUnlock and
	// maintenance completion re-check it before publishing unlocked state, so
	// a racing lock wins instead of leaving the runtime reporting unlocked
	// over a destroyed key session.
	lockGen uint64
	stateMu sync.RWMutex

	onLock              func()
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
// administration without permitting signing.
func (r *Runtime) SetRecovery() {
	r.stateMu.Lock()
	if r.activeMaintenanceID == 0 {
		r.state = SignerStateRecovery
	}
	r.stateMu.Unlock()
}

// IsRecovery reports whether signing is blocked pending explicit activation
// reconciliation.
func (r *Runtime) IsRecovery() bool {
	return r.GetState() == SignerStateRecovery
}

// Lock transitions the runtime to locked and invokes the configured lock
// callback once. It reports whether this call performed an unlocked->locked
// transition.
func (r *Runtime) Lock() bool {
	r.stateMu.Lock()
	wasActive := r.state == SignerStateUnlocked || r.state == SignerStateRecovery
	r.state = SignerStateLocked
	r.lockGen++
	onLock := r.onLock
	r.stateMu.Unlock()

	if !wasActive {
		return false
	}

	if onLock != nil {
		onLock()
	}
	return true
}

// BeginMaintenance clears published signing state through the normal on-lock
// callback without emitting an external lock decision. FinishMaintenance may
// restore unlocked state only if no later Lock changed lockGen.
func (r *Runtime) BeginMaintenance() MaintenanceToken {
	r.stateMu.Lock()
	r.state = SignerStateLocked
	r.lockGen++
	r.nextMaintenanceID++
	if r.nextMaintenanceID == 0 {
		r.nextMaintenanceID++
	}
	r.activeMaintenanceID = r.nextMaintenanceID
	token := MaintenanceToken{
		id:      r.activeMaintenanceID,
		lockGen: r.lockGen,
	}
	onLock := r.onLock
	r.stateMu.Unlock()

	if onLock != nil {
		onLock()
	}
	return token
}

// FinishMaintenance closes the maintenance fence. It restores unlocked state
// only when the caller requests publication and no later Lock changed
// lockGen. Failure and racing locks force the final state to locked.
func (r *Runtime) FinishMaintenance(
	token MaintenanceToken,
	republish bool,
) bool {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if token.id == 0 || r.activeMaintenanceID != token.id {
		return false
	}
	r.activeMaintenanceID = 0
	if republish &&
		r.lockGen == token.lockGen &&
		r.state == SignerStateLocked {
		r.state = SignerStateUnlocked
		return true
	}
	r.state = SignerStateLocked
	return false
}

// TryRecovery runs the keyring unlock function and enters recovery state
// unless a concurrent lock wins.
func (r *Runtime) TryRecovery(unlockFn func() error) (bool, string) {
	r.stateMu.RLock()
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
		onLock := r.onLock
		r.stateMu.Unlock()
		if onLock != nil {
			onLock()
		}
		return false, LockedDuringUnlockMessage
	}
	r.state = SignerStateRecovery
	r.stateMu.Unlock()
	return true, ""
}

// TryUnlock runs the supplied unlock function and, on success, transitions to
// unlocked - unless a Lock call raced the unlock function, in which case the
// lock wins: the lock callback runs again to destroy whatever the unlock
// function loaded, the state stays locked, and the unlock reports failure.
func (r *Runtime) TryUnlock(unlockFn func() (int, error), onUnlocked func()) (bool, int, string) {
	r.stateMu.RLock()
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
		onLock := r.onLock
		r.stateMu.Unlock()
		if onLock != nil {
			onLock()
		}
		return false, 0, LockedDuringUnlockMessage
	}
	r.state = SignerStateUnlocked
	r.stateMu.Unlock()

	if onUnlocked != nil {
		onUnlocked()
	}

	return true, keyCount, ""
}
