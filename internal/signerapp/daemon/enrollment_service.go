// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollment"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// enrollmentService builds the service the SSH server hands enrollment
// requests to: requests are queued on the product runtime and the connected
// operator, if any, is told at once.
func (fs *Signer) enrollmentService() enrollment.Service {
	var auditLog enrollment.AuditLogger
	if fs.auditLog != nil {
		auditLog = fs.auditLog
	}
	return enrollment.Service{
		Queue: func(key ssh.PublicKey, label, remoteAddr string) (bool, bool, error) {
			ir := fs.productRuntime()
			if ir == nil {
				return false, false, fmt.Errorf("product runtime is not initialized")
			}
			pending, added, err := ir.QueueEnrollment(key, label, remoteAddr)
			if err != nil && errors.Is(err, productruntime.ErrAppliedNotDurable) {
				// The request is in the live queue and the operator can act
				// on it, so it is recorded and announced as queued; only
				// its durability is in doubt, which the next queue write
				// repairs first.
				logWarnf("enrollment request from %s (key: %s) is queued but the queue write is not yet durable: %v", remoteAddr, ssh.FingerprintSHA256(key), err)
				return pending, added, nil
			}
			return pending, added, err
		},
		Notify:   fs.notifyEnrollmentRequest,
		AuditLog: auditLog,
		Logf:     logInfof,
	}
}

// notifyEnrollmentRequest tells the connected operator about a waiting
// request. Delivery is best effort: the request is in the queue whether or
// not an operator is connected, and the queue is shown again at login.
func (fs *Signer) notifyEnrollmentRequest(req enrollment.Request) {
	hub := fs.adminHub()
	if hub == nil {
		return
	}
	hub.SendClientEnrollmentRequest(&signerapproval.ClientEnrollmentRequest{
		ID:             req.ID,
		SSHFingerprint: req.Fingerprint,
		Label:          req.Label,
		RemoteAddr:     req.RemoteAddr,
		Timestamp:      req.RequestedAt.Unix(),
	})
}

// notifyPendingEnrollments tells the operator who just connected about every
// request still waiting, oldest first.
func (fs *Signer) notifyPendingEnrollments() {
	ir := fs.productRuntime()
	if ir == nil {
		return
	}
	for _, entry := range ir.PendingEnrollments() {
		fs.notifyEnrollmentRequest(enrollment.Request{
			ID:          enrollment.RequestID(entry.Fingerprint),
			Fingerprint: entry.Fingerprint,
			Label:       entry.Label,
			RemoteAddr:  entry.RemoteAddr,
			RequestedAt: entry.RequestedAt,
		})
	}
}
