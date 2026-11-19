// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

// newApprovalServiceWithAudit builds the approval service for one request.
func (fs *Signer) newApprovalServiceWithAudit(ir *productruntime.Runtime, auditLog signersigning.AuditRejectLogger) *signersigning.ApprovalService {
	userAutoApprove := ir.Config().UserAutoApprove()
	return &signersigning.ApprovalService{
		UserAutoApprove: &userAutoApprove,
		ApprovalWait: func() time.Duration {
			return ir.Config().ApprovalWait()
		},
		AuditLog: auditLog,
		Console:  signerConsole{},
		KnownAddresses: func() map[string]bool {
			return ir.KnownAddresses()
		},
		HasClient: func() bool {
			return fs.hasAdminClient()
		},
		RequestSigningApprovalPrompt: ir.RequestSigningApprovalPrompt,
		Chain:                        fs.chainReader(),
	}
}
