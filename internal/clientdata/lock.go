// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientdata

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const lockFileName = ".apclient.lock"

var (
	lockMu     sync.Mutex
	lockStates = make(map[string]bool)
	lockCond   = sync.NewCond(&lockMu)
)

// WithExclusiveLock serializes mutations to shared APCLIENT_DATA state.
// The lock is advisory and only effective for writers that participate.
// Nested acquisition by the same goroutine is not supported; callers that already
// hold the lock must avoid lock-taking helpers beneath them.
func WithExclusiveLock(dataDir string, fn func() error) error {
	if dataDir == "" {
		return fmt.Errorf("client data directory not set")
	}

	lockMu.Lock()
	for lockStates[dataDir] {
		lockCond.Wait()
	}
	lockStates[dataDir] = true
	lockMu.Unlock()
	defer releaseExclusiveLock(dataDir)

	if err := os.MkdirAll(dataDir, 0o770); err != nil {
		return fmt.Errorf("failed to create client data directory: %w", err)
	}

	lockPath := filepath.Join(dataDir, lockFileName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return fmt.Errorf("failed to open client lock file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock client data: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}()

	return fn()
}

func releaseExclusiveLock(dataDir string) {
	lockMu.Lock()
	defer lockMu.Unlock()
	delete(lockStates, dataDir)
	lockCond.Broadcast()
}
