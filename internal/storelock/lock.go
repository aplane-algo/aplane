// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const lockFileName = ".apstore.lock"

// ErrBusy indicates the store is already locked by another cooperating process.
var ErrBusy = errors.New("store is locked by another process")

// Guard holds a cooperative advisory flock on signer store state.
type Guard struct {
	f *os.File
}

// AcquireShared acquires a non-blocking shared lock for live readers/users of the store.
func AcquireShared(dataDir string) (*Guard, error) {
	return acquire(dataDir, syscall.LOCK_SH|syscall.LOCK_NB)
}

// AcquireExclusive acquires a non-blocking exclusive lock for offline mutations.
func AcquireExclusive(dataDir string) (*Guard, error) {
	return acquire(dataDir, syscall.LOCK_EX|syscall.LOCK_NB)
}

func acquire(dataDir string, how int) (*Guard, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("data directory not set")
	}
	if err := os.MkdirAll(dataDir, 0o770); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	lockPath := filepath.Join(dataDir, lockFileName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return nil, fmt.Errorf("failed to open store lock file: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("failed to lock store: %w", err)
	}

	return &Guard{f: f}, nil
}

// Close releases the held lock.
func (g *Guard) Close() error {
	if g == nil || g.f == nil {
		return nil
	}
	errUnlock := syscall.Flock(int(g.f.Fd()), syscall.LOCK_UN)
	errClose := g.f.Close()
	g.f = nil
	if errUnlock != nil {
		return errUnlock
	}
	return errClose
}
