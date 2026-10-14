// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

type signingAudit interface {
	signersigning.AuditLogger
	signersigning.AuditApproveLogger
	signersigning.AuditRejectLogger
	signersigning.AuditFailLogger
}

func (fs *Signer) newSigningServiceWithAudit(ir *productruntime.Runtime, auditLog signingAudit) *signersigning.Service {
	// One request, one policy snapshot: every slot of this request resolves
	// against the NodePolicy captured here, whatever reloads land later.
	nodePolicy := ir.NodePolicy()
	return &signersigning.Service{
		Planner:                       fs.newPlannerWithAudit(auditLog),
		Approval:                      fs.newApprovalServiceWithAudit(ir, auditLog),
		Executor:                      fs.newExecutionServiceWithAudit(auditLog),
		AuditLog:                      auditLog,
		Console:                       signerConsole{},
		GenerateTxnDescriptionFromTxn: fs.generateTransactionDescriptionFromTxn,
		IsUnlocked: func() bool {
			return ir.IsUnlocked()
		},
		BeforeExecute: func() (func(), *signersigning.ServiceError) {
			if !ir.IsUnlocked() {
				return nil, &signersigning.ServiceError{Kind: signersigning.ErrorLocked, Message: "signer is locked"}
			}
			return func() {}, nil
		},
		PolicyFor: nodePolicy.PolicyFor,
		HoldsCosignerKey: func(witnessKeyID string) bool {
			_, err := ir.FindKeyFile(witnessKeyID)
			return err == nil
		},
		Rotating: fs.rotatingDeps(ir),
	}
}
