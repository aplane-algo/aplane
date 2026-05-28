// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (fs *Signer) newExecutionServiceWithAudit(auditLog signersigning.AuditFailLogger) *signersigning.Executor {
	return &signersigning.Executor{
		AuditLog:          auditLog,
		Console:           signerConsole{},
		DecodeRuntimeArgs: signersigning.DecodeHexRuntimeArgs,
	}
}
