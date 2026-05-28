// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/signerapp/sshprovision"

func (fs *Signer) sshProvisioningService() sshprovision.Service {
	var auditLog sshprovision.AuditLogger
	if fs.auditLog != nil {
		auditLog = fs.auditLog
	}
	return sshprovision.Service{
		TokenRoot:                       fs.keyPaths.Root(),
		RequestTokenProvisioning:        fs.requestTokenProvisioning,
		RequestTokenProvisioningContext: fs.requestTokenProvisioningContext,
		AuditLog:                        auditLog,
		Logf:                            logInfof,
	}
}
