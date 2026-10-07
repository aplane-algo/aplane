// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import "github.com/aplane-algo/aplane/internal/signerapp/enrollment"

func (fs *Signer) enrollmentService() enrollment.Service {
	var auditLog enrollment.AuditLogger
	if fs.auditLog != nil {
		auditLog = fs.auditLog
	}
	return enrollment.Service{
		RequestEnrollmentContext: fs.requestClientEnrollmentContext,
		AuditLog:                 auditLog,
		Logf:                     logInfof,
	}
}
