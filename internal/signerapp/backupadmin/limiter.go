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
	RetryAfter(archivePath string) time.Duration
	RecordFailure(archivePath string)
	RecordSuccess(archivePath string)
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

func (l *RestoreAttemptLimiter) RetryAfter(archivePath string) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.attempts[archivePath]
	now := l.now()
	if state.nextAllowed.After(now) {
		return state.nextAllowed.Sub(now)
	}
	return 0
}

func (l *RestoreAttemptLimiter) RecordFailure(archivePath string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.attempts[archivePath]
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
	l.attempts[archivePath] = state
}

func (l *RestoreAttemptLimiter) RecordSuccess(archivePath string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, archivePath)
}

func RestoreRateLimitedError(retryAfter time.Duration) string {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	retryAfter = retryAfter.Round(time.Second)
	return fmt.Sprintf("restore attempts temporarily rate limited; retry after %s", retryAfter)
}
