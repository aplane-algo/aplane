// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// unauthenticatedStreams is the rate limited kinds of entry that a caller who
// has not authenticated can have written, and the summary each limit writes.
// The enrollment queue bounds the one other, CLIENT_ENROLLMENT_REQUESTED.
var unauthenticatedStreams = []struct {
	name    string
	write   func(*AuditLogger)
	is      func(AuditEntry) bool
	summary AuditEventType
}{
	{"client authentication", func(a *AuditLogger) { a.LogAuthFailed("127.0.0.1:1", "invalid_credentials") },
		func(e AuditEntry) bool { return e.Event == AuditAuthFailed }, AuditAuthFailuresSuppressed},
	{"admin login", func(a *AuditLogger) { a.LogAdminLoginFailedContext(adminserver.SessionContext{}, "wrong passphrase") },
		func(e AuditEntry) bool { return e.Event == AuditAdminLoginFailed }, AuditAdminLoginFailuresSuppressed},
	{"enroll connection", func(a *AuditLogger) { a.LogSSHSessionConnected("192.0.2.1:1", "SHA256:unknown", false) },
		func(e AuditEntry) bool { return e.Reason == "ssh-enroll" }, AuditEnrollSessionsSuppressed},
	{"store initialization", func(a *AuditLogger) { a.LogStoreInitializeFailed("passphrase is required") },
		func(e AuditEntry) bool { return e.Event == AuditStoreInitializeFailed }, AuditStoreInitFailuresSuppressed},
}

// Each stream a caller who has not authenticated can write to is limited and
// then summarized, and a flood of one leaves the others, and an enrolled
// client's connections, recorded.
func TestUnauthenticatedStreamsAreRateLimited(t *testing.T) {
	for _, flooded := range unauthenticatedStreams {
		t.Run(flooded.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			logger, err := NewAuditLogger(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_760_000_000, 0)
			for _, l := range logger.limiters() {
				l.now = func() time.Time { return now }
			}
			const flood = 1000
			for range flood {
				flooded.write(logger)
			}
			for _, other := range unauthenticatedStreams {
				if other.summary != flooded.summary {
					other.write(logger)
				}
			}
			logger.LogSSHSessionConnected("192.0.2.2:1", "SHA256:enrolled", true)
			logger.LogSSHSessionDisconnected("192.0.2.2:1", "SHA256:enrolled", true)
			if err := logger.Close(); err != nil {
				t.Fatal(err)
			}

			entries := readAuditEntries(t, path)
			count := func(is func(AuditEntry) bool) (n int) {
				for _, e := range entries {
					if is(e) {
						n++
					}
				}
				return n
			}
			if got := count(flooded.is); got != authFailureBurst {
				t.Errorf("a flood of %d wrote %d entries, want the burst of %d", flood, got, authFailureBurst)
			}
			for _, e := range entries {
				if e.Event == flooded.summary && e.SuppressedCount != flood-authFailureBurst {
					t.Errorf("summary = %+v, want %d suppressed", e, flood-authFailureBurst)
				}
			}
			if got := countEvents(entries, flooded.summary); got != 1 {
				t.Errorf("%s entries = %d, want 1", flooded.summary, got)
			}
			for _, other := range unauthenticatedStreams {
				if other.summary != flooded.summary && count(other.is) == 0 {
					t.Errorf("the flood hid the %s entry", other.name)
				}
			}
			if got := count(func(e AuditEntry) bool { return e.SSHFingerprint == "SHA256:enrolled" }); got != 2 {
				t.Errorf("an enrolled client's connection wrote %d entries, want 2", got)
			}
		})
	}
}

// An enroll connection writes both of its entries or neither, whatever came
// before it: a disconnect takes nothing from the limit, and one whose connect
// was suppressed stays suppressed after the limit refills.
func TestAnEnrollConnectionIsLoggedWholeOrNotAtAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	logger.enrollSessions.now = func() time.Time { return now }
	remote := func(i int) string { return fmt.Sprintf("192.0.2.1:%d", i) }
	const open = 2 * authFailureBurst
	for i := range open {
		logger.LogSSHSessionConnected(remote(i), "SHA256:unknown", false)
	}
	now = now.Add(time.Hour)
	for i := range open {
		logger.LogSSHSessionDisconnected(remote(i), "SHA256:unknown", false)
	}
	// The address of a connection that ended is free for another.
	logger.LogSSHSessionConnected(remote(0), "SHA256:unknown", false)
	logger.LogSSHSessionDisconnected(remote(0), "SHA256:unknown", false)
	logger.LogSSHSessionDisconnected(remote(0), "SHA256:unknown", false)
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	events := map[string][]AuditEventType{}
	for _, e := range readAuditEntries(t, path) {
		if e.RemoteAddr != "" {
			events[e.RemoteAddr] = append(events[e.RemoteAddr], e.Event)
		}
	}
	if len(events) != authFailureBurst {
		t.Fatalf("%d connections were logged, want the burst of %d", len(events), authFailureBurst)
	}
	for addr, got := range events {
		want := []AuditEventType{AuditSessionConnected, AuditSessionDisconnected}
		if addr == remote(0) {
			want = append(want, want...)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s wrote %v, want %v", addr, got, want)
		}
	}
}
