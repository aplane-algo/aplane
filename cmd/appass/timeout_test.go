// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// hungCommandLimit is how long a test lets an action run against a command
// that never finishes on its own before it calls the timeout missing.
const hungCommandLimit = 5 * time.Second

// shortCommandTimeout stops each external command after a moment.
func shortCommandTimeout(t *testing.T) {
	t.Helper()
	timeout, waitDelay := commandTimeout, commandWaitDelay
	commandTimeout, commandWaitDelay = 300*time.Millisecond, time.Second
	t.Cleanup(func() { commandTimeout, commandWaitDelay = timeout, waitDelay })
}

// writeCommand writes an executable script named name in dir.
func writeCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// hangingCommandBody is a script body that outlasts hungCommandLimit.
func hangingCommandBody(t *testing.T) string {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep command: %v", err)
	}
	return "exec " + sleep + " 10"
}

// A credential helper that never finishes is stopped, and the action ends on
// the result screen with the error. The working screen ignores keys, so a
// hung appass-systemd-creds once held appass until it was killed from
// another terminal.
func TestAHungCredentialHelperEndsTheActionWithAnError(t *testing.T) {
	shortCommandTimeout(t)
	stubSignerStopped(t)
	hang := hangingCommandBody(t)
	pathDir := t.TempDir()
	writeCommand(t, pathDir, "systemd-creds", "exit 0") // only looked up
	t.Setenv("PATH", pathDir)
	binDir := t.TempDir()
	writeCommand(t, binDir, "appass-systemd-creds", hang)

	svc := &serviceInfo{BinDir: binDir, StoreUID: os.Geteuid(), StoreGID: os.Getegid()}
	m := NewModel(t.TempDir(), svc, false)
	m.viewState = ViewPassphraseInput
	m.currentAction = "set-systemd-creds"
	m, _ = typePassphrase(t, m, typedPassphrase)
	m, _ = press(m, tea.KeyEnter)
	m, _ = typePassphrase(t, m, typedPassphrase)
	m, action := press(m, tea.KeyEnter)
	if action == nil {
		t.Fatal("confirming did not start the action")
	}

	start := time.Now()
	done := action()
	if elapsed := time.Since(start); elapsed > hungCommandLimit {
		t.Fatalf("the action ran %s against a hung helper, want it stopped", elapsed)
	}
	next, _ := m.Update(done)
	m = next.(Model)
	if m.viewState != ViewResult || !strings.Contains(m.resultError, "appass-systemd-creds did not finish within") {
		t.Fatalf("after the hung helper: view %v, error %q; want the result screen with the timeout", m.viewState, m.resultError)
	}
}

// A systemctl daemon-reload that never finishes is stopped and reported.
func TestAHungDaemonReloadIsStopped(t *testing.T) {
	shortCommandTimeout(t)
	hang := hangingCommandBody(t)
	pathDir := t.TempDir()
	writeCommand(t, pathDir, "systemctl", hang)
	t.Setenv("PATH", pathDir)
	unit := filepath.Join(t.TempDir(), "apsigner.service")
	if err := os.WriteFile(unit, []byte("[Unit]\nDescription=test\n\n[Service]\nExecStart=/bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := serviceFile
	serviceFile = unit
	t.Cleanup(func() { serviceFile = original })

	start := time.Now()
	err := ensureLoadCredentialInService(filepath.Join(t.TempDir(), "passphrase.cred"))
	if elapsed := time.Since(start); elapsed > hungCommandLimit {
		t.Fatalf("daemon-reload ran %s while hung, want it stopped", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "systemctl did not finish within") {
		t.Fatalf("ensureLoadCredentialInService error = %v, want the daemon-reload timeout", err)
	}
}
