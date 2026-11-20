// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerrest "github.com/aplane-algo/aplane/internal/signerapp/rest"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

func (fs *Signer) restService() signerrest.Service {
	return fs.restServiceWithSigningAudit(fs.signingAuditLogger(auditAttribution{}))
}

func (fs *Signer) restServiceWithSigningAudit(signingAudit signingAudit) signerrest.Service {
	return signerrest.Service{
		Deps: signerrest.Dependencies{
			NewSigningService: func(ir *productruntime.Runtime) signerrest.SigningService {
				return fs.newSigningServiceWithAudit(ir, signingAudit)
			},
			PlanGroup:    fs.planGroupWithAudit(signingAudit),
			EncodeTxnHex: txnutil.EncodeWithPrefixHex,
			KeyAdmin: keyadmin.Service{
				AuditLog:             optionalAuditLog[keyadmin.AuditLogger](fs.auditLog),
				Runtime:              fs.productRuntime(),
				MutationLock:         &fs.storeMutationLock,
				GenerateGenericLSig:  fs.generateGenericLSig,
				NetworkGenesisHashes: fs.networkGenesisHashes,
			},
			StoreHealth:          &fs.storeHealth,
			NetworkGenesisHashes: fs.networkGenesisHashes,
		},
	}
}
