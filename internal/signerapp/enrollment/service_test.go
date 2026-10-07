// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollment

import (
	"context"
	"testing"
	"time"
)

type auditRecorder struct {
	sshFingerprint string
	label          string
	remoteAddr     string
}

func (a *auditRecorder) LogClientEnrolled(sshFingerprint, label, remoteAddr string) {
	a.sshFingerprint = sshFingerprint
	a.label = label
	a.remoteAddr = remoteAddr
}

func TestServiceApproveContextUsesCanonicalRequestShape(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	svc := Service{
		Now: func() time.Time { return time.Unix(0, 12345) },
		RequestEnrollmentContext: func(gotCtx context.Context, requestID, sshFingerprint, label, remoteAddr string, timeout time.Duration) (bool, error) {
			called = true
			if gotCtx != ctx {
				t.Fatal("ApproveContext did not pass through caller context")
			}
			if requestID != "enroll-12345" {
				t.Fatalf("requestID = %q, want enroll-12345", requestID)
			}
			if sshFingerprint != "SHA256:test" || label != "laptop" || remoteAddr != "10.0.0.1" {
				t.Fatalf("request args = %q %q %q", sshFingerprint, label, remoteAddr)
			}
			if timeout != ApprovalTimeout {
				t.Fatalf("timeout = %v, want %v", timeout, ApprovalTimeout)
			}
			return true, nil
		},
	}

	ok, err := svc.ApproveContext(ctx, "SHA256:test", "laptop", "10.0.0.1")
	if err != nil || !ok || !called {
		t.Fatalf("ApproveContext() = %v, %v (called %v)", ok, err, called)
	}
}

func TestServiceApproveContextWithoutRequesterFails(t *testing.T) {
	ok, err := Service{}.ApproveContext(context.Background(), "SHA256:test", "", "10.0.0.1")
	if err == nil || ok {
		t.Fatalf("ApproveContext() = %v, %v, want an error", ok, err)
	}
}

func TestServiceAuditEnrolledRecordsAndLogs(t *testing.T) {
	audit := &auditRecorder{}
	var logged string
	svc := Service{AuditLog: audit, Logf: func(format string, args ...interface{}) { logged = format }}
	svc.AuditEnrolled("SHA256:test", "laptop", "10.0.0.1")
	if audit.sshFingerprint != "SHA256:test" || audit.label != "laptop" || audit.remoteAddr != "10.0.0.1" {
		t.Fatalf("audit = %+v", audit)
	}
	if logged == "" {
		t.Fatal("AuditEnrolled did not log")
	}
}
