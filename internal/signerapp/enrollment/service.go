// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package enrollment approves and records client key enrollment: the
// operator-approved flow by which an SSH key becomes an enrolled client.
// No credential is issued; the key itself is the client's credential.
package enrollment

import (
	"context"
	"fmt"
	"time"
)

// ApprovalTimeout bounds how long an enrollment request waits for the
// operator.
const ApprovalTimeout = 5 * time.Minute

// AuditLogger records enrollment outcomes.
type AuditLogger interface {
	LogClientEnrolled(sshFingerprint, label, remoteAddr string)
}

// Service brokers an enrollment request to the operator and audits the
// result.
type Service struct {
	// RequestEnrollmentContext asks the connected operator to approve the
	// key. It is canceled when the SSH client disconnects.
	RequestEnrollmentContext func(ctx context.Context, requestID, sshFingerprint, label, remoteAddr string, timeout time.Duration) (bool, error)
	AuditLog                 AuditLogger
	Logf                     func(format string, args ...interface{})
	Now                      func() time.Time
}

// ApproveContext asks the operator to approve enrolling the key with the
// given fingerprint and label.
func (s Service) ApproveContext(ctx context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
	if s.RequestEnrollmentContext == nil {
		return false, fmt.Errorf("enrollment requester not configured")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	requestID := fmt.Sprintf("enroll-%d", now().UnixNano())
	return s.RequestEnrollmentContext(ctx, requestID, sshFingerprint, label, remoteAddr, ApprovalTimeout)
}

// AuditEnrolled records a completed enrollment, after the acknowledgement
// reached the client.
func (s Service) AuditEnrolled(sshFingerprint, label, remoteAddr string) {
	if s.AuditLog != nil {
		s.AuditLog.LogClientEnrolled(sshFingerprint, label, remoteAddr)
	}
	if s.Logf != nil {
		if label != "" {
			s.Logf("client key enrolled for %s (key: %s, label: %q)", remoteAddr, sshFingerprint, label)
		} else {
			s.Logf("client key enrolled for %s (key: %s)", remoteAddr, sshFingerprint)
		}
	}
}
