// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = original }()
	fn()
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Log and logDurable go through the same steps and differ only in what they
// do with a failure: Log warns on stderr, logDurable returns it.
func TestLogAndLogDurableReportEachFailureTheirOwnWay(t *testing.T) {
	newLogger := func(t *testing.T, configure func(*faultyFile)) (*AuditLogger, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "audit.log")
		if configure != nil {
			useFaultyFiles(t, configure)
		}
		logger, err := NewAuditLogger(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = logger.Close() })
		return logger, path
	}
	unavailable := func(t *testing.T, logger *AuditLogger, path string) {
		t.Helper()
		_ = logger.file.Close()
		logger.file = nil
		if err := os.RemoveAll(filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
	}
	fileHas := func(t *testing.T, path, want string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), want) {
			t.Fatalf("log = %q, %v; want %s", data, err, want)
		}
	}

	t.Run("written", func(t *testing.T) {
		logger, path := newLogger(t, nil)
		if out := captureStderr(t, func() { logger.Log(AuditEntry{Event: "plain"}) }); out != "" {
			t.Fatalf("Log stderr = %q", out)
		}
		var err error
		if out := captureStderr(t, func() { err = logger.logDurable(AuditEntry{Event: "durable"}) }); out != "" || err != nil {
			t.Fatalf("logDurable = %v, stderr %q", err, out)
		}
		fileHas(t, path, `"event":"plain"`)
		fileHas(t, path, `"event":"durable"`)
	})

	t.Run("closed", func(t *testing.T) {
		logger, _ := newLogger(t, nil)
		_ = logger.Close()
		if out := captureStderr(t, func() { logger.Log(AuditEntry{Event: "late"}) }); out != "" {
			t.Fatalf("Log stderr = %q, want nothing", out)
		}
		var err error
		if out := captureStderr(t, func() { err = logger.logDurable(AuditEntry{Event: "late"}) }); out != "" || err == nil || err.Error() != "audit log is closed" {
			t.Fatalf("logDurable = %v, stderr %q", err, out)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		logger, path := newLogger(t, nil)
		unavailable(t, logger, path)
		if out := captureStderr(t, func() { logger.Log(AuditEntry{Event: "dropped"}) }); out != "Warning: audit log unavailable, dropping entry\n" {
			t.Fatalf("Log stderr = %q", out)
		}
		var err error
		if out := captureStderr(t, func() { err = logger.logDurable(AuditEntry{Event: "dropped"}) }); out != "" || err == nil || err.Error() != "audit log unavailable at "+path {
			t.Fatalf("logDurable = %v, stderr %q", err, out)
		}
	})

	t.Run("failed rotation", func(t *testing.T) {
		const warning = "Warning: failed to rotate audit log: close current log: simulated close failure\n"
		logger, path := newLogger(t, func(f *faultyFile) { f.failClose = true })
		logger.written = maxAuditLogSize
		if out := captureStderr(t, func() { logger.Log(AuditEntry{Event: "after-rotation"}) }); out != warning {
			t.Fatalf("Log stderr = %q", out)
		}
		logger.written = maxAuditLogSize
		var err error
		if out := captureStderr(t, func() { err = logger.logDurable(AuditEntry{Event: "durable-after-rotation"}) }); out != warning || err != nil {
			t.Fatalf("logDurable = %v, stderr %q", err, out)
		}
		fileHas(t, path, `"event":"after-rotation"`)
		fileHas(t, path, `"event":"durable-after-rotation"`)
	})

	t.Run("failed write", func(t *testing.T) {
		logger, _ := newLogger(t, func(f *faultyFile) { f.shortWrites = 2 })
		if out := captureStderr(t, func() { logger.Log(AuditEntry{Event: "short"}) }); out != "Warning: write audit entry: simulated short write\n" {
			t.Fatalf("Log stderr = %q", out)
		}
		var err error
		if out := captureStderr(t, func() { err = logger.logDurable(AuditEntry{Event: "short"}) }); out != "" || err == nil || err.Error() != "write audit entry: simulated short write" {
			t.Fatalf("logDurable = %v, stderr %q", err, out)
		}
	})
}
