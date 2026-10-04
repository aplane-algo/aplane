// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readAuditEntries(t *testing.T, path string) []AuditEntry {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var entries []AuditEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func countEvents(entries []AuditEntry, event AuditEventType) int {
	n := 0
	for _, entry := range entries {
		if entry.Event == event {
			n++
		}
	}
	return n
}

// A flood of unauthenticated failures cannot rotate earlier entries out of
// the log: after the burst, failures are counted into one summary instead of
// being written one by one.
func TestAuthFailureFloodIsSummarized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	a.authFailures.now = func() time.Time { return now }

	a.Log(AuditEntry{Event: AuditSignApproved, Outcome: "approved"})
	const flood = 10_000
	for i := 0; i < flood; i++ {
		a.LogAuthFailed("127.0.0.1:1", "invalid_credentials")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	entries := readAuditEntries(t, path)
	if got := countEvents(entries, AuditSignApproved); got != 1 {
		t.Fatalf("earlier entry count = %d, want 1", got)
	}
	if got := countEvents(entries, AuditAuthFailed); got != authFailureBurst {
		t.Fatalf("individual AUTH_FAILED entries = %d, want the burst of %d", got, authFailureBurst)
	}
	if got := countEvents(entries, AuditAuthFailuresSuppressed); got != 1 {
		t.Fatalf("summary entries = %d, want 1", got)
	}
	summary := entries[len(entries)-1]
	if summary.Event != AuditAuthFailuresSuppressed || summary.SuppressedCount != flood-authFailureBurst {
		t.Fatalf("summary = %+v, want %d suppressed", summary, flood-authFailureBurst)
	}
}

// The bucket refills over time, so sporadic failures are all logged.
func TestAuthFailuresRefillOverTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	a.authFailures.now = func() time.Time { return now }
	for i := 0; i < authFailureBurst+1; i++ {
		a.LogAuthFailed("127.0.0.1:1", "invalid_credentials")
	}
	now = now.Add(authFailureRefillInterval)
	a.LogAuthFailed("127.0.0.1:1", "invalid_credentials")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	if got := countEvents(entries, AuditAuthFailed); got != authFailureBurst+1 {
		t.Fatalf("individual AUTH_FAILED entries = %d, want %d", got, authFailureBurst+1)
	}
	if got := countEvents(entries, AuditAuthFailuresSuppressed); got != 1 {
		t.Fatalf("summary entries = %d, want 1 for the one suppressed failure", got)
	}
}

// Failures by an authenticated principal are never rate limited.
func TestAttributedAuthFailuresAreNotLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < authFailureBurst*2; i++ {
		a.LogAuthFailedAttributed("product-admin", "127.0.0.1:1", "unauthorized: sign")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if got := countEvents(readAuditEntries(t, path), AuditAuthFailed); got != authFailureBurst*2 {
		t.Fatalf("attributed AUTH_FAILED entries = %d, want %d", got, authFailureBurst*2)
	}
}

// A suppressed count is written on a timer, without waiting for Close or
// another failure.
func TestAuthFailureSummaryIsWrittenWithoutClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.authFailures.summaryAfter = 20 * time.Millisecond
	for i := 0; i < authFailureBurst+3; i++ {
		a.LogAuthFailed("127.0.0.1:1", "invalid_credentials")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countEvents(readAuditEntries(t, path), AuditAuthFailuresSuppressed) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("suppressed failures were not summarized on the timer")
}

// Close waits for a timer-driven summary that is already being written, so
// the suppressed count is never lost to a concurrent shutdown.
func TestCloseKeepsInFlightAuthFailureSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.authFailures.summaryAfter = time.Hour // only the explicit flush below runs
	for j := 0; j < authFailureBurst+1; j++ {
		a.LogAuthFailed("127.0.0.1:1", "invalid_credentials")
	}
	writing := make(chan struct{})
	release := make(chan struct{})
	a.authFailures.beforeSummary = func() {
		close(writing)
		<-release
	}
	flushed := make(chan struct{})
	go func() {
		a.flushAuthFailureSummary()
		close(flushed)
	}()
	<-writing

	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while a summary was being written", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-flushed
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if got := countEvents(readAuditEntries(t, path), AuditAuthFailuresSuppressed); got != 1 {
		t.Fatalf("summary entries = %d, want 1", got)
	}
}
