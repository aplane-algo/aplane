// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollment"
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
			return ir.QueueEnrollment(key, label, remoteAddr)
		},
		Notify: fs.notifyEnrollmentRequest,
		Changed: func(fingerprint string) {
			fs.notifyEnrollmentChanged(protocol.EnrollmentChangeRequested, fingerprint)
		},
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

// notifyEnrollmentChanged tells the connected operator that the enrollment
// queue or the client registry changed, so a screen showing either list
// re-fetches it. Delivery is best effort, like every notification.
func (fs *Signer) notifyEnrollmentChanged(reason, fingerprint string) {
	if hub := fs.adminHub(); hub != nil {
		hub.NotifyEnrollmentChanged(adminproto.EnrollmentChangedNotification{Reason: reason, Fingerprint: fingerprint})
	}
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
