// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerrest "github.com/aplane-algo/aplane/internal/signerapp/rest"
)

func (fs *Signer) restService() signerrest.Service {
	var auditLog keyadmin.AuditLogger
	if fs.auditLog != nil {
		auditLog = fs.auditLog
	}
	var signerAudit signingAudit
	if fs.auditLog != nil {
		signerAudit = fs.auditLog
	}
	return fs.restServiceWithAudit(auditLog, signerAudit)
}

func (fs *Signer) restServiceWithSigningAudit(auditLog signingAudit) signerrest.Service {
	var keyAudit keyadmin.AuditLogger
	if fs.auditLog != nil {
		keyAudit = fs.auditLog
	}
	return fs.restServiceWithAudit(keyAudit, auditLog)
}

func (fs *Signer) restServiceWithAudit(keyAudit keyadmin.AuditLogger, signingAudit signingAudit) signerrest.Service {
	return signerrest.Service{
		Deps: signerrest.Dependencies{
			NewSigningService: func(ir *productruntime.Runtime) signerrest.SigningService {
				return fs.newSigningServiceWithAudit(ir, signingAudit)
			},
			PlanGroup:    fs.planGroupWithAudit(signingAudit),
			EncodeTxnHex: encodeTxnToHex,
			KeyAdmin: keyadmin.Service{
				AuditLog: keyAudit,
				MutationLock: func() keyadmin.Locker {
					return &fs.storeMutationLock
				},
			},
			GenerateGenericLSig: fs.generateGenericLSigForRuntimeContext,
		},
	}
}
