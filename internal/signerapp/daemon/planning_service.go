// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (fs *Signer) newPlannerWithAudit(auditLog signersigning.AuditLogger) *signersigning.Planner {
	resolver := fs.genesisHashResolver()
	return signersigning.NewPlanner(signerPlannerDeps{signer: fs}, signersigning.PlannerOptions{
		AuditLog:               auditLog,
		Console:                signerConsole{},
		GenerateTxnDescription: fs.generateTransactionDescription,
		GenesisHashResolver:    resolver,
	})
}

func (fs *Signer) genesisHashResolver() apconfig.GenesisHashNetworkResolver {
	if fs == nil {
		return apconfig.DefaultGenesisHashNetworkResolver()
	}
	cfg := fs.ConfigSnapshot()
	resolver, err := apconfig.NewGenesisHashNetworkResolver(cfg.GenesisHashNetworks)
	if err != nil {
		return apconfig.DefaultGenesisHashNetworkResolver()
	}
	return resolver
}

func (fs *Signer) planGroupWithAudit(auditLog signersigning.AuditLogger) func(signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError) {
	return func(req signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError) {
		return fs.newPlannerWithAudit(auditLog).PlanGroup(req)
	}
}

type signerPlannerDeps struct {
	signer *Signer
}

func (d signerPlannerDeps) Snapshot() signersigning.PlannerIdentitySnapshot {
	ir := d.signer.runtime
	if ir == nil {
		return signersigning.PlannerIdentitySnapshot{}
	}
	// KeyIndexSnapshot deep-clones per call, so the snapshot (including its
	// Parameters maps and bounded metadata) is owned by this request.
	snapshot := ir.KeyIndexSnapshot()
	keyMetadata := make(map[string]signersigning.PlannerKeyMetadata, len(snapshot.KeyMetadata))
	for selector, metadata := range snapshot.KeyMetadata {
		keyMetadata[selector] = signersigning.PlannerKeyMetadata{
			Category: metadata.Category, PublicKeyHex: metadata.PublicKeyHex, Parameters: metadata.Parameters,
			BoundedAuthorization: metadata.BoundedAuthorization,
			LogicSigResources:    metadata.LogicSigResources,
		}
	}
	return signersigning.PlannerIdentitySnapshot{
		Revision:    snapshot.Revision,
		KeyFiles:    snapshot.KeyFiles,
		KeyTypes:    snapshot.KeyTypes,
		KeyMetadata: keyMetadata,
	}
}
