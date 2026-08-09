// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerprobe

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCheckStoppedWhenSocketMissing(t *testing.T) {
	dataDir := t.TempDir()
	wantPath := filepath.Join(dataDir, "aplane.sock")

	result, err := Check(dataDir, Options{
		Dial: func(path string, timeout time.Duration) (net.Conn, error) {
			if path != wantPath {
				t.Fatalf("dial path = %q, want %q", path, wantPath)
			}
			if timeout != DefaultTimeout {
				t.Fatalf("timeout = %v, want %v", timeout, DefaultTimeout)
			}
			return nil, syscall.ENOENT
		},
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if result.State != StateStopped {
		t.Fatalf("state = %q, want %q", result.State, StateStopped)
	}
	if result.IPCPath != wantPath {
		t.Fatalf("IPCPath = %q, want %q", result.IPCPath, wantPath)
	}
}

func TestCheckStoppedWhenSocketRefused(t *testing.T) {
	dataDir := t.TempDir()

	result, err := Check(dataDir, Options{
		Dial: func(string, time.Duration) (net.Conn, error) {
			return nil, syscall.ECONNREFUSED
		},
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if result.State != StateStopped {
		t.Fatalf("state = %q, want %q", result.State, StateStopped)
	}
}

func TestCheckRunningWhenSocketAccepts(t *testing.T) {
	dataDir := t.TempDir()

	result, err := Check(dataDir, Options{
		Dial: func(string, time.Duration) (net.Conn, error) {
			return &stubConn{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !result.Running() {
		t.Fatalf("running = false, want true")
	}
}

func TestCheckUsesConfiguredIPCPath(t *testing.T) {
	dataDir := t.TempDir()
	ipcPath := filepath.Join(dataDir, "custom.sock")
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("ipc_path: "+ipcPath+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := Check(dataDir, Options{
		Dial: func(path string, _ time.Duration) (net.Conn, error) {
			if path != ipcPath {
				t.Fatalf("dial path = %q, want %q", path, ipcPath)
			}
			return nil, syscall.ENOENT
		},
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if result.IPCPath != ipcPath {
		t.Fatalf("IPCPath = %q, want %q", result.IPCPath, ipcPath)
	}
}

func TestCheckReturnsErrorForUnexpectedDialFailure(t *testing.T) {
	dataDir := t.TempDir()

	result, err := Check(dataDir, Options{
		Dial: func(string, time.Duration) (net.Conn, error) {
			return nil, errors.New("boom")
		},
	})
	if err == nil {
		t.Fatal("Check returned nil error, want non-nil")
	}
	if result.IPCPath == "" {
		t.Fatal("IPCPath is empty on dial error")
	}
}

func TestResolveIPCPathReturnsParseError(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("ipc_path: [\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := ResolveIPCPath(dataDir)
	if err == nil {
		t.Fatal("ResolveIPCPath returned nil error, want non-nil")
	}
	if !strings.Contains(err.Error(), "failed to parse config file") {
		t.Fatalf("error = %v, want parse context", err)
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
