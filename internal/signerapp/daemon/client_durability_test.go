// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollment"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A revocation whose registry write fails after the rename has taken
// effect: the key is refused, the revocation is audited, and the durability
// failure is reported to the operator on top of that.
func TestRevokeClientKeyAppliedNotDurableIsAudited(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	ir := productruntime.New(productruntime.Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	fs := &Signer{auditLog: auditLog, runtime: ir}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.EnrollAuthorizedKey(key, "laptop"); err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(key)

	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	_, err = fs.RevokeClientKey(adminserver.SessionContext{}, ir, fingerprint)
	if !errors.Is(err, productruntime.ErrAppliedNotDurable) {
		t.Fatalf("RevokeClientKey() error = %v, want the applied-not-durable failure", err)
	}
	if ir.HasAuthorizedKey(key) {
		t.Fatal("revoked key is still authorized")
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), string(signeraudit.AuditClientKeyRevoked)) || !strings.Contains(string(data), fingerprint) {
		t.Fatalf("audit log lacks the revocation that took effect: %q", data)
	}
}

// An approval whose registry write fails after the rename has enrolled the
// key: CLIENT_ENROLLED is recorded and the operator is told about the
// durability failure, and the request stays listed for a repeat approval.
func TestApproveClientEnrollmentAppliedNotDurableIsAudited(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	ir := productruntime.New(productruntime.Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	fs := &Signer{auditLog: auditLog, runtime: ir}

	key := testClientKey(t)
	fingerprint := ssh.FingerprintSHA256(key)
	if pending, _, err := ir.QueueEnrollment(key, "laptop", "10.0.0.1:1"); err != nil || !pending {
		t.Fatalf("QueueEnrollment() = %v, %v", pending, err)
	}

	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	label, err := fs.ApproveClientEnrollment(adminserver.SessionContext{}, ir, fingerprint, "")
	if !errors.Is(err, productruntime.ErrAppliedNotDurable) || label != "laptop" {
		t.Fatalf("ApproveClientEnrollment() = (%q, %v), want the applied-not-durable failure", label, err)
	}
	if !ir.HasAuthorizedKey(key) || len(ir.PendingEnrollments()) != 1 {
		t.Fatalf("after the incomplete approval: authorized = %v, pending = %d", ir.HasAuthorizedKey(key), len(ir.PendingEnrollments()))
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), string(signeraudit.AuditClientEnrolled)) || !strings.Contains(string(data), fingerprint) {
		t.Fatalf("audit log lacks the enrollment that took effect: %q", data)
	}
}

// A request that reached the live queue through a write that is not yet
// durable is still a queued request: the client is told it is pending, it
// is audited, and the operator is notified.
func TestEnrollmentRequestAppliedNotDurableIsQueued(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	ir := productruntime.New(productruntime.Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	fs := &Signer{auditLog: auditLog, runtime: ir}
	svc := fs.enrollmentService()
	var notified []string
	svc.Notify = func(req enrollment.Request) { notified = append(notified, req.Fingerprint) }

	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	key := testClientKey(t)
	fingerprint := ssh.FingerprintSHA256(key)
	if pending, err := svc.Request(key, "laptop", "10.0.0.1:1"); err != nil || !pending {
		t.Fatalf("Request() = (%v, %v), want pending without error", pending, err)
	}
	if got := ir.PendingEnrollments(); len(got) != 1 || got[0].Fingerprint != fingerprint {
		t.Fatalf("pending = %+v, want the request", got)
	}
	if len(notified) != 1 || notified[0] != fingerprint {
		t.Fatalf("notified = %v, want the request announced once", notified)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), string(signeraudit.AuditClientEnrollmentRequested)) || !strings.Contains(string(data), fingerprint) {
		t.Fatalf("audit log lacks the queued request: %q", data)
	}
}
