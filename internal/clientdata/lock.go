// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientdata

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

const lockFileName = ".apclient.lock"

var (
	lockMu sync.Mutex
	// lockHolders maps a held dataDir to the goroutine that holds it, so a
	// nested acquisition by the same goroutine fails loudly instead of
	// deadlocking on the condition variable (and then on the flock).
	lockHolders = make(map[string]uint64)
	lockCond    = sync.NewCond(&lockMu)
)

// WithExclusiveLock serializes mutations to shared APCLIENT_DATA state.
// The lock is advisory and only effective for writers that participate.
// The lock is not reentrant: a caller that already holds it must use the
// *Locked variants of the cache mutators beneath it. Nested acquisition by
// the same goroutine returns an error instead of self-deadlocking.
func WithExclusiveLock(dataDir string, fn func() error) error {
	if dataDir == "" {
		return fmt.Errorf("client data directory not set")
	}

	gid := goroutineID()
	lockMu.Lock()
	for {
		holder, held := lockHolders[dataDir]
		if !held {
			break
		}
		if holder == gid {
			lockMu.Unlock()
			return fmt.Errorf("nested WithExclusiveLock for %s on the same goroutine: callers already holding the lock must use the *Locked variants", dataDir)
		}
		lockCond.Wait()
	}
	lockHolders[dataDir] = gid
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

	unlock, err := lockFileExclusive(f)
	if err != nil {
		return fmt.Errorf("failed to lock client data: %w", err)
	}
	defer unlock()

	return fn()
}

func releaseExclusiveLock(dataDir string) {
	lockMu.Lock()
	defer lockMu.Unlock()
	delete(lockHolders, dataDir)
	lockCond.Broadcast()
}

// goroutineID extracts the current goroutine's id from its stack header
// ("goroutine N [..."). The format has been stable across Go releases and is
// used only to detect nested acquisition, never for correctness of the lock
// itself.
func goroutineID() uint64 {
	buf := make([]byte, 64)
	buf = buf[:runtime.Stack(buf, false)]
	buf = bytes.TrimPrefix(buf, []byte("goroutine "))
	if i := bytes.IndexByte(buf, ' '); i > 0 {
		if id, err := strconv.ParseUint(string(buf[:i]), 10, 64); err == nil {
			return id
		}
	}
	return 0
}
