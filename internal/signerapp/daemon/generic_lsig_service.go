// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
)

func (fs *Signer) genericLSigGenerator() keyadmin.GenericLSigGenerator {
	var auditLog keyadmin.AuditLogger
	if fs.auditLog != nil {
		auditLog = fs.auditLog
	}
	cfg := fs.ConfigSnapshot()
	return keyadmin.GenericLSigGenerator{
		Config:    &cfg,
		MakeAlgod: fs.makeAlgod,
		AuditLog:  auditLog,
	}
}

func (fs *Signer) generateGenericLSigForIdentityContext(ctx context.Context, ir *identity.Runtime, keyType string, parameters map[string]string) (string, error) {
	return fs.genericLSigGenerator().GenerateContext(ctx, ir, keyType, parameters)
}
