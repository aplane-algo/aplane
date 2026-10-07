// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package enrollment records client key enrollment requests: a client that
// asks to be enrolled is queued for the operator and answered at once; the
// operator approves or rejects the request later. No credential is issued;
// the key itself is the client's credential.
package enrollment

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// AuditLogger records enrollment requests.
type AuditLogger interface {
	LogClientEnrollmentRequested(sshFingerprint, label, remoteAddr string)
}

// Request is a queued enrollment request as shown to the operator.
type Request struct {
	// ID identifies the notification; it is derived from the fingerprint so
	// the same key never shows as two requests.
	ID          string
	Fingerprint string
	Label       string
	RemoteAddr  string
	RequestedAt time.Time
}

// RequestID is the notification ID for a key's enrollment request.
func RequestID(fingerprint string) string {
	return "enroll-" + fingerprint
}

// Service queues enrollment requests and tells the operator about them.
type Service struct {
	// Queue records the request. It reports pending when the request now
	// waits for the operator and added when it was new rather than a
	// refresh; pending is false for a key that is already enrolled.
	Queue func(key ssh.PublicKey, label, remoteAddr string) (pending, added bool, err error)
	// Notify tells a connected operator about a new request. It may be nil
	// and must not block.
	Notify func(req Request)
	// Changed reports that the live queue now holds the request, new or
	// refreshed (a repeat updates the entry's label, address, and time), so
	// a screen listing the queue can re-fetch it. It may be nil and must
	// not block.
	Changed  func(fingerprint string)
	AuditLog AuditLogger
	Logf     func(format string, args ...interface{})
	Now      func() time.Time
}

// Request records a client's enrollment request and reports whether it is
// now waiting for the operator (as opposed to the key being enrolled
// already). A full queue is reported as an error the client can read. A
// request that reached the live queue through a write that is not yet
// durable (productruntime.ErrAppliedNotDurable) is recorded and announced
// like any other, since the operator can act on it, but the client is
// answered with an error so it retries: the retry refreshes the entry and is
// acknowledged only once the queue is durable.
func (s Service) Request(key ssh.PublicKey, label, remoteAddr string) (pending bool, err error) {
	if s.Queue == nil {
		return false, fmt.Errorf("enrollment queue not configured")
	}
	if key == nil {
		return false, fmt.Errorf("enrollment key is required")
	}
	fingerprint := ssh.FingerprintSHA256(key)
	pending, added, err := s.Queue(key, label, remoteAddr)
	notDurable := err != nil && errors.Is(err, productruntime.ErrAppliedNotDurable)
	if err != nil && !notDurable {
		if errors.Is(err, enrollqueue.ErrQueueFull) {
			return false, fmt.Errorf("enrollment queue is full; ask the operator to clear it and try again")
		}
		s.logf("failed to record enrollment request from %s (key: %s): %v", remoteAddr, fingerprint, err)
		return false, fmt.Errorf("failed to record enrollment request")
	}
	switch {
	case !pending:
		s.logf("enrollment request from %s: key already enrolled (key: %s)", remoteAddr, fingerprint)
	case added:
		if s.AuditLog != nil {
			s.AuditLog.LogClientEnrollmentRequested(fingerprint, label, remoteAddr)
		}
		s.logf("enrollment request queued from %s (key: %s, label: %q); approve it in apadmin", remoteAddr, fingerprint, label)
		if s.Notify != nil {
			s.Notify(Request{ID: RequestID(fingerprint), Fingerprint: fingerprint, Label: label, RemoteAddr: remoteAddr, RequestedAt: s.now()})
		}
		if s.Changed != nil {
			s.Changed(fingerprint)
		}
	default:
		s.logf("enrollment request refreshed from %s (key: %s); it is still waiting for the operator", remoteAddr, fingerprint)
		if s.Changed != nil {
			s.Changed(fingerprint)
		}
	}
	if notDurable {
		s.logf("enrollment request from %s (key: %s) is queued but the queue write is not yet durable; the client is told to retry: %v", remoteAddr, fingerprint, err)
		return pending, fmt.Errorf("enrollment request recorded but not yet durable; retry the request")
	}
	return pending, nil
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Service) logf(format string, args ...interface{}) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}
