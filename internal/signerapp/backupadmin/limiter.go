// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"sync"
	"time"
)

const (
	restoreAttemptInitialDelay = time.Second
	restoreAttemptMaxDelay     = 30 * time.Second
)

type RestoreLimiter interface {
	RetryAfter(identityID, archivePath string) time.Duration
	RecordFailure(identityID, archivePath string)
	RecordSuccess(identityID, archivePath string)
}

type RestoreAttemptLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	attempts map[string]restoreAttemptState
}

type restoreAttemptState struct {
	failures    int
	nextAllowed time.Time
}

func NewRestoreAttemptLimiter(now func() time.Time) *RestoreAttemptLimiter {
	if now == nil {
		now = time.Now
	}
	return &RestoreAttemptLimiter{
		now:      now,
		attempts: make(map[string]restoreAttemptState),
	}
}

func (l *RestoreAttemptLimiter) RetryAfter(identityID, archivePath string) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.attempts[restoreAttemptKey(identityID, archivePath)]
	now := l.now()
	if state.nextAllowed.After(now) {
		return state.nextAllowed.Sub(now)
	}
	return 0
}

func (l *RestoreAttemptLimiter) RecordFailure(identityID, archivePath string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	key := restoreAttemptKey(identityID, archivePath)
	state := l.attempts[key]
	state.failures++
	delay := restoreAttemptInitialDelay
	for i := 1; i < state.failures; i++ {
		delay *= 2
		if delay >= restoreAttemptMaxDelay {
			delay = restoreAttemptMaxDelay
			break
		}
	}
	state.nextAllowed = l.now().Add(delay)
	l.attempts[key] = state
}

func (l *RestoreAttemptLimiter) RecordSuccess(identityID, archivePath string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, restoreAttemptKey(identityID, archivePath))
}

func restoreAttemptKey(identityID, archivePath string) string {
	return identityID + "\x00" + archivePath
}

func RestoreRateLimitedError(retryAfter time.Duration) string {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	retryAfter = retryAfter.Round(time.Second)
	return fmt.Sprintf("restore attempts temporarily rate limited; retry after %s", retryAfter)
}
