// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type auditRecorder struct {
	sshFingerprint string
	label          string
	remoteAddr     string
	calls          int
}

func (a *auditRecorder) LogClientEnrollmentRequested(sshFingerprint, label, remoteAddr string) {
	a.sshFingerprint = sshFingerprint
	a.label = label
	a.remoteAddr = remoteAddr
	a.calls++
}

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestServiceRequestQueuesAuditsAndNotifies(t *testing.T) {
	key := testKey(t)
	audit := &auditRecorder{}
	var notified []Request
	now := time.Unix(1700000000, 0)
	svc := Service{
		Queue: func(got ssh.PublicKey, label, remoteAddr string) (bool, bool, error) {
			if ssh.FingerprintSHA256(got) != ssh.FingerprintSHA256(key) || label != "laptop" || remoteAddr != "10.0.0.1" {
				t.Fatalf("queue args = %s %q %q", ssh.FingerprintSHA256(got), label, remoteAddr)
			}
			return true, true, nil
		},
		Notify:   func(req Request) { notified = append(notified, req) },
		AuditLog: audit,
		Now:      func() time.Time { return now },
	}
	pending, err := svc.Request(key, "laptop", "10.0.0.1")
	if err != nil || !pending {
		t.Fatalf("Request() = %v, %v", pending, err)
	}
	fingerprint := ssh.FingerprintSHA256(key)
	if audit.calls != 1 || audit.sshFingerprint != fingerprint || audit.label != "laptop" || audit.remoteAddr != "10.0.0.1" {
		t.Fatalf("audit = %+v", audit)
	}
	if len(notified) != 1 || notified[0].ID != RequestID(fingerprint) || notified[0].Fingerprint != fingerprint || !notified[0].RequestedAt.Equal(now) {
		t.Fatalf("notified = %+v", notified)
	}
}

func TestServiceRequestRefreshAndAlreadyEnrolledAreQuiet(t *testing.T) {
	key := testKey(t)
	audit := &auditRecorder{}
	notified := 0
	svc := Service{
		Queue:    func(ssh.PublicKey, string, string) (bool, bool, error) { return true, false, nil },
		Notify:   func(Request) { notified++ },
		AuditLog: audit,
	}
	if pending, err := svc.Request(key, "", ""); err != nil || !pending {
		t.Fatalf("refresh Request() = %v, %v", pending, err)
	}
	svc.Queue = func(ssh.PublicKey, string, string) (bool, bool, error) { return false, false, nil }
	if pending, err := svc.Request(key, "", ""); err != nil || pending {
		t.Fatalf("enrolled Request() = %v, %v", pending, err)
	}
	if audit.calls != 0 || notified != 0 {
		t.Fatalf("audit calls = %d notified = %d, want none", audit.calls, notified)
	}
}

func TestServiceRequestReportsFullQueueAndHidesOtherFailures(t *testing.T) {
	key := testKey(t)
	var logged []string
	svc := Service{
		Queue: func(ssh.PublicKey, string, string) (bool, bool, error) { return false, false, enrollqueue.ErrQueueFull },
		Logf:  func(format string, args ...interface{}) { logged = append(logged, format) },
	}
	if _, err := svc.Request(key, "", "10.0.0.1"); err == nil || !strings.Contains(err.Error(), "queue is full") {
		t.Fatalf("full queue error = %v", err)
	}
	svc.Queue = func(ssh.PublicKey, string, string) (bool, bool, error) {
		return false, false, errors.New("disk is read-only")
	}
	_, err := svc.Request(key, "", "10.0.0.1")
	if err == nil || strings.Contains(err.Error(), "read-only") {
		t.Fatalf("storage failure error = %v, want a generic message", err)
	}
	if len(logged) == 0 {
		t.Fatal("storage failure was not logged")
	}
	if _, err := (Service{}).Request(key, "", ""); err == nil {
		t.Fatal("Request() without a queue succeeded")
	}
}

// A request that reached the live queue through a write that is not yet
// durable is recorded and announced, but the client is answered with an
// error so it retries.
func TestServiceRequestAppliedNotDurableIsRecordedButRefused(t *testing.T) {
	key := testKey(t)
	audit := &auditRecorder{}
	var notified []Request
	svc := Service{
		Queue: func(ssh.PublicKey, string, string) (bool, bool, error) {
			return true, true, fmt.Errorf("%w: injected dir sync failure", productruntime.ErrAppliedNotDurable)
		},
		Notify:   func(req Request) { notified = append(notified, req) },
		AuditLog: audit,
	}
	pending, err := svc.Request(key, "laptop", "10.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "not yet durable") || !pending {
		t.Fatalf("Request() = (%v, %v), want pending with the not-yet-durable error", pending, err)
	}
	if audit.calls != 1 || len(notified) != 1 {
		t.Fatalf("audit calls = %d, notified = %d, want the request recorded and announced once", audit.calls, len(notified))
	}
}
