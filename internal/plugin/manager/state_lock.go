// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const pluginStateLockFileName = ".aplane-plugin-state.lock"

var (
	errPluginStateLockHeld = errors.New("plugin state lock held")

	pluginStateLocksMu     sync.Mutex
	pluginStateLockHolders = make(map[string]struct{})
)

type pluginStateLock struct {
	file               *os.File
	unlock             func()
	releaseReservation func()
	once               sync.Once
}

func lockPluginStateDir(stateDir string) (*pluginStateLock, error) {
	if stateDir == "" {
		return nil, nil
	}

	releaseReservation, err := reservePluginStateLock(stateDir)
	if err != nil {
		return nil, err
	}

	lockPath := filepath.Join(stateDir, pluginStateLockFileName)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseReservation()
		return nil, fmt.Errorf("failed to open plugin state lock file: %w", err)
	}

	unlock, err := tryLockPluginStateFile(file)
	if err != nil {
		_ = file.Close()
		releaseReservation()
		if errors.Is(err, errPluginStateLockHeld) {
			return nil, fmt.Errorf("%w by another shell: %s", ErrPluginStateInUse, stateDir)
		}
		return nil, fmt.Errorf("failed to lock plugin state directory: %w", err)
	}

	return &pluginStateLock{
		file:               file,
		unlock:             unlock,
		releaseReservation: releaseReservation,
	}, nil
}

func reservePluginStateLock(stateDir string) (func(), error) {
	lockID, err := filepath.Abs(stateDir)
	if err != nil {
		lockID = filepath.Clean(stateDir)
	}

	pluginStateLocksMu.Lock()
	defer pluginStateLocksMu.Unlock()
	if _, exists := pluginStateLockHolders[lockID]; exists {
		return nil, fmt.Errorf("%w by another shell: %s", ErrPluginStateInUse, stateDir)
	}
	pluginStateLockHolders[lockID] = struct{}{}
	return func() {
		pluginStateLocksMu.Lock()
		delete(pluginStateLockHolders, lockID)
		pluginStateLocksMu.Unlock()
	}, nil
}

func (l *pluginStateLock) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.unlock != nil {
			l.unlock()
		}
		if l.file != nil {
			_ = l.file.Close()
		}
		if l.releaseReservation != nil {
			l.releaseReservation()
		}
	})
}
