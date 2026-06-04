// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

type signingAudit interface {
	signersigning.AuditLogger
	signersigning.AuditApproveLogger
	signersigning.AuditRejectLogger
	signersigning.AuditFailLogger
}

func (fs *Signer) newSigningServiceForIdentityWithAudit(ir *identity.Runtime, auditLog signingAudit) *signersigning.Service {
	return &signersigning.Service{
		Planner:                       fs.newPlannerWithAudit(auditLog),
		Approval:                      fs.newApprovalServiceForIdentityWithAudit(ir, auditLog),
		Executor:                      fs.newExecutionServiceWithAudit(auditLog),
		AuditLog:                      auditLog,
		Console:                       signerConsole{},
		GenerateTxnDescriptionFromTxn: fs.generateTransactionDescriptionFromTxn,
		IsUnlocked: func() bool {
			return ir.IsUnlocked() && !ir.IsDecommissioned()
		},
		BeforeExecute: func() (func(), *signersigning.ServiceError) {
			release, err := ir.BeginOperation()
			if err != nil {
				return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: err.Error()}
			}
			if !ir.IsUnlocked() {
				release()
				return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: "signer is locked"}
			}
			return release, nil
		},
		Policy:            ir.Policy(),
		AttestationPolicy: ir.AttestationPolicy(),
	}
}
