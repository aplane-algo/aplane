// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

// newApprovalServiceWithAudit builds the approval service for one request.
func (fs *Signer) newApprovalServiceWithAudit(ir *productruntime.Runtime, auditLog signersigning.AuditRejectLogger) *signersigning.ApprovalService {
	return &signersigning.ApprovalService{
		UserAutoApprove:              ir.Config().UserAutoApprove(),
		ApprovalWait:                 ir.Config().ApprovalWait,
		AuditLog:                     auditLog,
		Console:                      signerConsole{},
		KnownAddresses:               ir.KnownAddresses,
		HasClient:                    fs.hasAdminClient,
		RequestSigningApprovalPrompt: ir.RequestSigningApprovalPrompt,
		Chain:                        fs.chainReader(),
	}
}
