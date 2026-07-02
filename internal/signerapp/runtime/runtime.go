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
)

const LockedDuringUnlockMessage = "signer locked during unlock"

func (s SignerState) String() string {
	switch s {
	case SignerStateLocked:
		return "locked"
	case SignerStateUnlocked:
		return "unlocked"
	default:
		return "unknown"
	}
}

// Runtime owns signer lock state.
type Runtime struct {
	state SignerState
	// lockGen increments on every Lock call. TryUnlock snapshots it before
	// running the unlock function and re-checks it under stateMu before
	// transitioning to unlocked, so a lock that raced the unlock wins instead
	// of leaving the runtime reporting unlocked over a destroyed key session.
	lockGen uint64
	stateMu sync.RWMutex

	onLock func()
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
	r.state = SignerStateUnlocked
	r.stateMu.Unlock()
}

// Lock transitions the runtime to locked and invokes the configured lock
// callback once. It reports whether this call performed an unlocked->locked
// transition.
func (r *Runtime) Lock() bool {
	r.stateMu.Lock()
	wasUnlocked := r.state == SignerStateUnlocked
	r.state = SignerStateLocked
	r.lockGen++
	onLock := r.onLock
	r.stateMu.Unlock()

	if !wasUnlocked {
		return false
	}

	if onLock != nil {
		onLock()
	}
	return true
}

// TryUnlock runs the supplied unlock function and, on success, transitions to
// unlocked - unless a Lock call raced the unlock function, in which case the
// lock wins: the lock callback runs again to destroy whatever the unlock
// function loaded, the state stays locked, and the unlock reports failure.
func (r *Runtime) TryUnlock(unlockFn func() (int, error), onUnlocked func()) (bool, int, string) {
	r.stateMu.RLock()
	gen := r.lockGen
	r.stateMu.RUnlock()

	keyCount, err := unlockFn()
	if err != nil {
		return false, 0, err.Error()
	}

	r.stateMu.Lock()
	if r.lockGen != gen {
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
