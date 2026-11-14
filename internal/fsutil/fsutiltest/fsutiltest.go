// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package fsutiltest holds test helpers built on fsutil.TestHook.
package fsutiltest

import (
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// HeldWrite is an update running in the background with its durable write
// held at one step.
type HeldWrite struct {
	reached    chan struct{}
	released   chan struct{}
	releaseErr error
	result     chan error
	once       sync.Once
	err        error
}

// Hold runs update with the durable write held at op on path until Finish.
// Every exit path of the test, a failed assertion included, releases the
// hold and waits for update before it clears the hook, so no update is left
// parked inside the write holding a mutation lock and clearing the hook
// never races it. A test whose other cleanup could wait on that lock
// registers it before calling Hold, so this cleanup runs first.
func Hold(t *testing.T, op fsutil.HookOp, path string, update func() error) *HeldWrite {
	t.Helper()
	h := &HeldWrite{reached: make(chan struct{}), released: make(chan struct{}), result: make(chan error, 1)}
	var reachOnce sync.Once
	fsutil.TestHook = func(got fsutil.HookOp, gotPath string) error {
		if got == op && gotPath == path {
			reachOnce.Do(func() { close(h.reached) })
			<-h.released
			return h.releaseErr
		}
		return nil
	}
	go func() { h.result <- update() }()
	t.Cleanup(func() {
		_ = h.Finish(nil)
		fsutil.TestHook = nil
	})
	select {
	case <-h.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the write never reached the held step")
	}
	return h
}

// Finish lets the held step return err (nil lets it go on) and returns the
// update's result. Later calls return the same result.
func (h *HeldWrite) Finish(err error) error {
	h.once.Do(func() {
		h.releaseErr = err
		close(h.released)
		h.err = <-h.result
	})
	return h.err
}
