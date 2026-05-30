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
	state   SignerState
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

// Lock transitions the runtime to locked and invokes the configured lock callback once.
func (r *Runtime) Lock() {
	r.stateMu.Lock()
	wasUnlocked := r.state == SignerStateUnlocked
	r.state = SignerStateLocked
	onLock := r.onLock
	r.stateMu.Unlock()

	if !wasUnlocked {
		return
	}

	if onLock != nil {
		onLock()
	}
}

// TryUnlock runs the supplied unlock function and, on success, transitions to unlocked.
func (r *Runtime) TryUnlock(unlockFn func() (int, error), onUnlocked func()) (bool, int, string) {
	keyCount, err := unlockFn()
	if err != nil {
		return false, 0, err.Error()
	}

	r.stateMu.Lock()
	r.state = SignerStateUnlocked
	r.stateMu.Unlock()

	if onUnlocked != nil {
		onUnlocked()
	}

	return true, keyCount, ""
}
