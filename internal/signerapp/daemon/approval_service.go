// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (fs *Signer) newApprovalServiceForIdentityWithAudit(ir *identity.Runtime, auditLog signersigning.AuditRejectLogger) *signersigning.ApprovalService {
	userAutoApprove := ir.Config().UserAutoApprove()
	return &signersigning.ApprovalService{
		UserAutoApprove: &userAutoApprove,
		ApprovalWait: func() time.Duration {
			return ir.Config().ApprovalWait()
		},
		AuditLog:                      auditLog,
		Console:                       signerConsole{},
		GenerateTxnDescriptionFromTxn: fs.generateTransactionDescriptionFromTxn,
		KnownAddresses: func(identityID string) map[string]bool {
			target := fs.registry.Get(identityID)
			if target == nil {
				return nil
			}
			return target.KnownAddresses()
		},
		HasClient:                             fs.hasClientForIdentity,
		RequestSigningApproval:                fs.requestSigningApproval,
		RequestSigningApprovalResponse:        fs.requestSigningApprovalResponse,
		RequestSigningApprovalContext:         fs.requestSigningApprovalContext,
		RequestSigningApprovalResponseContext: fs.requestSigningApprovalResponseContext,
		EncodeTxnToHex:                        encodeTxnToHex,
	}
}
