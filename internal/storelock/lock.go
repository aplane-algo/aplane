// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	storeLockFileName  = ".apstore.lock"
	signerLockFileName = ".apsigner.lock"
)

// ErrBusy indicates the lock is held by another cooperating process.
var ErrBusy = errors.New("lock is held by another process")

// Guard holds a cooperative advisory flock on signer store state.
type Guard struct {
	f *os.File
}

// AcquireShared acquires a non-blocking shared lock for live readers/users of the store.
func AcquireShared(dataDir string) (*Guard, error) {
	return acquire(dataDir, storeLockFileName, syscall.LOCK_SH|syscall.LOCK_NB)
}

// AcquireExclusive acquires a non-blocking exclusive lock for offline mutations.
func AcquireExclusive(dataDir string) (*Guard, error) {
	return acquire(dataDir, storeLockFileName, syscall.LOCK_EX|syscall.LOCK_NB)
}

// AcquireSigner acquires the non-blocking exclusive lock that one apsigner holds
// on its data directory for as long as it runs. It is a lock of its own, beside
// the store lock a signer shares with offline readers.
func AcquireSigner(dataDir string) (*Guard, error) {
	return acquire(dataDir, signerLockFileName, syscall.LOCK_EX|syscall.LOCK_NB)
}

func acquire(dataDir, name string, how int) (*Guard, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("data directory not set")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	lockPath := filepath.Join(dataDir, name)
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to wrap lock file %s", lockPath)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to inspect lock file %s: %w", lockPath, err)
		}
		return nil, fmt.Errorf("lock path is not a regular file: %s", lockPath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("lock file must have exactly one link: %s", lockPath)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to set permissions of lock file %s: %w", lockPath, err)
	}

	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("failed to lock %s: %w", lockPath, err)
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
