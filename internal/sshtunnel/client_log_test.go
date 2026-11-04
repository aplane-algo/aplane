// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	previous := slog.Default()
	flags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	var out bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &out
}

func TestConnectionLossIsLoggedAsAWarning(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		want   string
	}{
		{"remote close", "", "connection closed by remote server"},
		{"revocation", DisconnectReasonKeyRevoked, "this client's key was revoked by the signer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureLog(t)
			client := NewClient("example.com", 22, 0, "", "")
			called := false
			client.SetDisconnectCallback(func() { called = true })
			client.connected = true
			client.disconnectReason = tc.reason

			client.handleDisconnect()

			got := out.String()
			for _, want := range []string{"level=WARN", "component=ssh", tc.want} {
				if !strings.Contains(got, want) {
					t.Fatalf("log = %q, want %q", got, want)
				}
			}
			if !called {
				t.Fatal("the disconnect callback didn't run")
			}
		})
	}
}

// A cosigner connection has no disconnect callback, and its loss still needs
// reporting, because a plain remote close is only logged here.
func TestConnectionLossIsReportedWithoutACallback(t *testing.T) {
	out := captureLog(t)
	client := NewClient("example.com", 22, 0, "", "")
	client.connected = true

	client.handleDisconnect()

	got := out.String()
	for _, want := range []string{"level=WARN", "connection closed by remote server"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log = %q, want %q", got, want)
		}
	}
}

func TestConnectionLossIsReportedOnce(t *testing.T) {
	out := captureLog(t)
	client := NewClient("example.com", 22, 0, "", "")
	calls := 0
	client.SetDisconnectCallback(func() { calls++ })
	client.connected = true

	client.handleDisconnect()
	client.handleDisconnect()

	if got := strings.Count(out.String(), "connection closed by remote server"); got != 1 || calls != 1 {
		t.Fatalf("reported %d times, called back %d times; want once each", got, calls)
	}
}

// Cosigner connections are closed after each use, so a local close that read as a
// remote one would warn every time.
func TestLocalCloseIsNotReportedAsARemoteClose(t *testing.T) {
	out := captureLog(t)
	client := NewClient("example.com", 22, 0, "", "")
	client.connected = true

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	client.handleDisconnect() // What the connection monitor does once Wait returns.

	if out.Len() != 0 {
		t.Fatalf("log = %q, a local close isn't a lost connection", out.String())
	}
}

func TestConnectionErrorIsAWarningUnlessItIsAPlainClose(t *testing.T) {
	out := captureLog(t)

	logConnectionError(fmt.Errorf("wrapped: %w", io.EOF))
	if got := out.String(); !strings.Contains(got, "level=DEBUG") {
		t.Fatalf("log = %q, want debug: the close is reported separately", got)
	}

	out.Reset()
	logConnectionError(errors.New("connection reset"))
	if got := out.String(); !strings.Contains(got, "level=WARN") {
		t.Fatalf("log = %q, want a warning", got)
	}
}

func TestLocalDisconnectIsNotReported(t *testing.T) {
	out := captureLog(t)
	client := NewClient("example.com", 22, 0, "", "")
	client.SetDisconnectCallback(func() {})

	client.handleDisconnect() // Not connected.

	if out.Len() != 0 {
		t.Fatalf("log = %q, want nothing", out.String())
	}
}

func TestIdentityCreatedIsLoggedWithoutAHandler(t *testing.T) {
	out := captureLog(t)
	path := filepath.Join(t.TempDir(), "id")
	client := NewClient("example.com", 22, 0, path, "")

	if _, err := client.generateIdentityKey(path); err != nil {
		t.Fatalf("generateIdentityKey() error = %v", err)
	}

	got := out.String()
	for _, want := range []string{"level=WARN", "generated a new SSH identity key", "fingerprint=SHA256:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log = %q, want %q", got, want)
		}
	}
}

func TestHandlerOwnsTheHostTrustPrompt(t *testing.T) {
	out := captureLog(t)
	client := NewClient("example.com", 22, 0, "", filepath.Join(t.TempDir(), "known_hosts"))
	client.SetHostKeyApprovalHandler(func(string, string) (bool, error) { return false, nil })
	callback, err := client.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}

	_ = callback("example.com", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, signer.PublicKey())

	if strings.Contains(out.String(), "example.com") {
		t.Fatalf("the prompt's text reached the log: %q", out.String())
	}
}
