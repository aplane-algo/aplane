// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"time"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (fs *Signer) newApprovalServiceWithAudit(ir *productruntime.Runtime, auditLog signersigning.AuditRejectLogger) *signersigning.ApprovalService {
	userAutoApprove := ir.Config().UserAutoApprove()
	return &signersigning.ApprovalService{
		UserAutoApprove: &userAutoApprove,
		ApprovalWait: func() time.Duration {
			return ir.Config().ApprovalWait()
		},
		AuditLog:                      auditLog,
		Console:                       signerConsole{},
		GenerateTxnDescriptionFromTxn: fs.generateTransactionDescriptionFromTxn,
		KnownAddresses: func() map[string]bool {
			return ir.KnownAddresses()
		},
		HasClient: func() bool {
			return fs.hasAdminClient()
		},
		RequestSigningApproval: func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			return ir.RequestSigningApproval(requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		},
		RequestSigningApprovalResponse: func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
			return ir.RequestSigningApprovalResponse(requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		},
		RequestSigningApprovalContext: func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
			return ir.RequestSigningApprovalContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		},
		RequestSigningApprovalResponseContext: func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
			return ir.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		},
		EncodeTxnToHex: encodeTxnToHex,
	}
}
