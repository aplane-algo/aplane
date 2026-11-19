// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build unix

package apshellcli

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
)

// processGone reports whether pid has ended: no such process, or only its
// zombie left for its new parent to reap.
func processGone(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	// The state follows the parenthesized command name.
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

// A cancelled `!` command whose output is captured, as an embedded host's
// is, ends with every process it started, not with its shell alone.
func TestCancelledCapturedShellCommandLeavesNoProcessBehind(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(session.Shutdown)
	pidFile := filepath.Join(t.TempDir(), "pid")
	returned := make(chan error, 1)
	go func() {
		_, _, err := session.ExecuteLineCaptured("!sleep 30 & echo $! > " + pidFile + "; wait")
		returned <- err
	}()

	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for pid == 0 {
		if data, err := os.ReadFile(pidFile); err == nil && strings.HasSuffix(string(data), "\n") {
			if pid, err = strconv.Atoi(strings.TrimSpace(string(data))); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the shell command never started its child")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	session.Cancel()
	if err := <-returned; err == nil || !strings.Contains(err.Error(), "shell command stopped") {
		t.Fatalf("the line returned %v, want it stopped", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("the shell command's child %d is still running after the cancel", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
