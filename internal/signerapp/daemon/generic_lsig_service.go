// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
)

func (fs *Signer) genericLSigGenerator() keyadmin.GenericLSigGenerator {
	cfg := fs.ConfigSnapshot()
	return keyadmin.GenericLSigGenerator{
		Config:    &cfg,
		MakeAlgod: fs.makeAlgod,
		AuditLog:  optionalAuditLog[keyadmin.AuditLogger](fs.auditLog),
	}
}

func (fs *Signer) generateGenericLSig(ctx context.Context, keyType string, parameters map[string]string) (string, error) {
	return fs.genericLSigGenerator().GenerateContext(ctx, fs.productRuntime(), keyType, parameters)
}
