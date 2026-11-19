// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

type sshStopperFunc func(context.Context) error

func (f sshStopperFunc) StopContext(ctx context.Context) error {
	return f(ctx)
}

func TestStopSSHRuntimePropagatesLifecycleContextAndDetachesRuntime(t *testing.T) {
	t.Parallel()

	sshCtx, cancelSSH := context.WithCancel(context.Background())
	stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	wantErr := errors.New("stop result")
	called := false
	rt := &sshRuntime{
		ctx:    sshCtx,
		cancel: cancelSSH,
		stopper: sshStopperFunc(func(ctx context.Context) error {
			called = true
			if ctx != stopCtx {
				t.Fatal("SSH stopper received a different context from lifecycle shutdown")
			}
			select {
			case <-sshCtx.Done():
			default:
				t.Fatal("SSH runtime context was not canceled before StopContext")
			}
			return wantErr
		}),
	}
	signer := &Signer{sshRuntime: rt}

	if err := signer.stopSSHRuntime(stopCtx); !errors.Is(err, wantErr) {
		t.Fatalf("stopSSHRuntime() error = %v, want %v", err, wantErr)
	}
	if !called {
		t.Fatal("stopSSHRuntime() did not call the SSH StopContext seam")
	}
	if signer.sshRuntime != nil || signer.sshServer != nil {
		t.Fatal("stopSSHRuntime() left the stopped SSH runtime published")
	}
}

// SSH session entries named only the product admin, so the audit log could
// not say which client key a connection belonged to. Each now carries the
// fingerprint of the key that opened it, enrolled or asking to be, beside
// the fields it had.
func TestSSHSessionAuditEntriesNameTheClientKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = auditLog.Close() }()
	cb := (&Signer{}).sshSessionCallback(auditLog)

	cb(sshtunnel.SessionEvent{RemoteAddr: "10.0.0.2:1", Fingerprint: "SHA256:enrolled", EnrolledKey: true, Connected: true})
	cb(sshtunnel.SessionEvent{RemoteAddr: "10.0.0.2:1", Fingerprint: "SHA256:enrolled", EnrolledKey: true})
	cb(sshtunnel.SessionEvent{RemoteAddr: "10.0.0.3:1", Fingerprint: "SHA256:asking", Connected: true})

	want := []AuditEntry{
		{Event: AuditSessionConnected, Outcome: "connected", RemoteAddr: "10.0.0.2:1", SSHFingerprint: "SHA256:enrolled"},
		{Event: AuditSessionDisconnected, Outcome: "disconnected", RemoteAddr: "10.0.0.2:1", SSHFingerprint: "SHA256:enrolled"},
		{Event: AuditSessionConnected, Outcome: "connected", RemoteAddr: "10.0.0.3:1", SSHFingerprint: "SHA256:asking"},
	}
	entries := readAuditEntries(t, path)
	if len(entries) != len(want) {
		t.Fatalf("entries = %+v, want %d", entries, len(want))
	}
	for i, entry := range entries {
		w := want[i]
		w.Timestamp = entry.Timestamp
		w.Principal = auth.SystemProductAdminPrincipalID
		w.RequesterPrincipal = auth.SystemProductAdminPrincipalID
		w.Reason = "ssh"
		if !reflect.DeepEqual(entry, w) {
			t.Errorf("entry %d = %+v, want %+v", i, entry, w)
		}
	}
}
