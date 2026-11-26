// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// What connections that have not proven an enrolled key may print: anyone who
// can reach the port can open them. The first unenrolledLogBurst lines print,
// then one per unenrolledLogRefill, and the count of the rest a minute after
// the first of them, so a flood cannot fill the signer's log.
const (
	unenrolledLogBurst        = 20
	unenrolledLogRefill       = 3 * time.Second
	unenrolledLogSummaryAfter = time.Minute
)

// unenrolledLog is the token bucket over those lines.
type unenrolledLog struct {
	mu         sync.Mutex
	out        io.Writer
	now        func() time.Time
	tokens     int
	refilledAt time.Time
	suppressed int
	summary    *time.Timer
	// summaryAfter is unenrolledLogSummaryAfter; tests may shorten it.
	summaryAfter time.Duration
	// closed is set when the server stops: a line a handler prints after
	// that arms no summary.
	closed bool
}

func newUnenrolledLog(out io.Writer) *unenrolledLog {
	return &unenrolledLog{out: out, now: time.Now, tokens: unenrolledLogBurst, summaryAfter: unenrolledLogSummaryAfter}
}

// printf prints the line, or counts it toward the next summary.
func (l *unenrolledLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.refilledAt.IsZero() {
		l.refilledAt = now
	}
	if refills := int(now.Sub(l.refilledAt) / unenrolledLogRefill); refills > 0 {
		l.tokens = min(unenrolledLogBurst, l.tokens+refills)
		l.refilledAt = l.refilledAt.Add(time.Duration(refills) * unenrolledLogRefill)
	}
	if l.tokens > 0 {
		l.tokens--
		_, _ = fmt.Fprintf(l.out, format, args...)
		return
	}
	if l.suppressed == 0 && !l.closed {
		l.summary = time.AfterFunc(l.summaryAfter, l.flush)
	}
	l.suppressed++
}

// close prints the count of the lines not printed, and arms no summary after.
func (l *unenrolledLog) close() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.flush()
}

// flush prints how many lines were not, if any.
func (l *unenrolledLog) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.summary != nil {
		l.summary.Stop()
		l.summary = nil
	}
	if l.suppressed == 0 {
		return
	}
	lines := "lines"
	if l.suppressed == 1 {
		lines = "line"
	}
	_, _ = fmt.Fprintf(l.out, "[SSH] %d more %s about connections without an enrolled key were not printed\n", l.suppressed, lines)
	l.suppressed = 0
}
