// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSignerRunningFalseWhenSocketMissing(t *testing.T) {
	dataDir := t.TempDir()

	dialSignerIPCMu.Lock()
	origDial := dialSignerIPC
	dialSignerIPC = func(socketPath string) (net.Conn, error) {
		return nil, syscall.ENOENT
	}
	dialSignerIPCMu.Unlock()
	defer func() { dialSignerIPCMu.Lock(); dialSignerIPC = origDial; dialSignerIPCMu.Unlock() }()

	running, socketPath, err := signerRunning(dataDir)
	if err != nil {
		t.Fatalf("signerRunning returned error: %v", err)
	}
	if running {
		t.Fatalf("running = true, want false")
	}

	wantPath := filepath.Join(dataDir, "aplane.sock")
	if socketPath != wantPath {
		t.Fatalf("socketPath = %q, want %q", socketPath, wantPath)
	}
}

func TestSignerRunningTrueWhenSocketAcceptsConnections(t *testing.T) {
	dataDir := t.TempDir()
	socketPath := filepath.Join(dataDir, "aplane.sock")

	dialSignerIPCMu.Lock()
	origDial := dialSignerIPC
	dialSignerIPC = func(path string) (net.Conn, error) {
		if path != socketPath {
			t.Fatalf("dial socket path = %q, want %q", path, socketPath)
		}
		return &stubConn{}, nil
	}
	dialSignerIPCMu.Unlock()
	defer func() { dialSignerIPCMu.Lock(); dialSignerIPC = origDial; dialSignerIPCMu.Unlock() }()

	running, gotPath, err := signerRunning(dataDir)
	if err != nil {
		t.Fatalf("signerRunning returned error: %v", err)
	}
	if !running {
		t.Fatalf("running = false, want true")
	}
	if gotPath != socketPath {
		t.Fatalf("socketPath = %q, want %q", gotPath, socketPath)
	}
}

func TestRequireSignerStoppedReturnsErrorWhenRunning(t *testing.T) {
	dataDir := t.TempDir()
	socketPath := filepath.Join(dataDir, "aplane.sock")

	dialSignerIPCMu.Lock()
	origDial := dialSignerIPC
	dialSignerIPC = func(path string) (net.Conn, error) {
		if path != socketPath {
			t.Fatalf("dial socket path = %q, want %q", path, socketPath)
		}
		return &stubConn{}, nil
	}
	dialSignerIPCMu.Unlock()
	defer func() { dialSignerIPCMu.Lock(); dialSignerIPC = origDial; dialSignerIPCMu.Unlock() }()

	err := requireSignerStopped(dataDir)
	if err == nil {
		t.Fatal("requireSignerStopped returned nil, want error")
	}
}

func TestSignerRunningReturnsErrorForUnexpectedDialFailure(t *testing.T) {
	dataDir := t.TempDir()

	dialSignerIPCMu.Lock()
	origDial := dialSignerIPC
	dialSignerIPC = func(string) (net.Conn, error) {
		return nil, errors.New("boom")
	}
	dialSignerIPCMu.Unlock()
	defer func() { dialSignerIPCMu.Lock(); dialSignerIPC = origDial; dialSignerIPCMu.Unlock() }()

	_, _, err := signerRunning(dataDir)
	if err == nil {
		t.Fatal("signerRunning returned nil error, want non-nil")
	}
}

type stubConn struct{}

func (s *stubConn) Read([]byte) (int, error)         { return 0, nil }
func (s *stubConn) Write([]byte) (int, error)        { return 0, nil }
func (s *stubConn) Close() error                     { return nil }
func (s *stubConn) LocalAddr() net.Addr              { return nil }
func (s *stubConn) RemoteAddr() net.Addr             { return nil }
func (s *stubConn) SetDeadline(time.Time) error      { return nil }
func (s *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubConn) SetWriteDeadline(time.Time) error { return nil }
