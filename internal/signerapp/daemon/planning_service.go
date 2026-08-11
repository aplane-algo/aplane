// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	txsigning "github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
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

func (fs *Signer) planGroupWithAudit(auditLog signersigning.AuditLogger) func(string, signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError) {
	return func(identityID string, req signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError) {
		return fs.newPlannerWithAudit(auditLog).PlanGroup(identityID, req)
	}
}

type signerPlannerDeps struct {
	signer *Signer
}

func (d signerPlannerDeps) Snapshot(identityID string) signersigning.PlannerIdentitySnapshot {
	ir := d.signer.registry.Get(identityID)
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
		LSigSizes:   snapshot.LSigSizes,
		KeyMetadata: keyMetadata,
	}
}

func (d signerPlannerDeps) NetworkParams(genesisHash types.Digest) signersigning.PlannerNetworkParams {
	if d.signer == nil {
		return signersigning.PlannerNetworkParams{MinTxnFee: txsigning.DefaultMinFee}
	}
	cfg := d.signer.ConfigSnapshot()
	resolver, err := apconfig.NewGenesisHashNetworkResolver(cfg.GenesisHashNetworks)
	if err != nil {
		return signersigning.PlannerNetworkParams{MinTxnFee: txsigning.DefaultMinFee}
	}
	network, ok := resolver.NetworkForGenesisHashBytes(genesisHash[:])
	if !ok {
		return signersigning.PlannerNetworkParams{MinTxnFee: txsigning.DefaultMinFee}
	}
	algodCfg, cfgErr := cfg.GetAlgodConfig(network)
	if cfgErr != nil || algodCfg.Server == "" {
		return signersigning.PlannerNetworkParams{MinTxnFee: txsigning.DefaultMinFee}
	}
	var algodClient *algod.Client
	if d.signer.makeAlgod != nil {
		algodClient, err = d.signer.makeAlgod(algodCfg.Server, algodCfg.Token)
	} else {
		algodClient, err = txsigning.CreateAlgodClient(algodCfg.Server, algodCfg.Token)
	}
	if err != nil || algodClient == nil {
		return signersigning.PlannerNetworkParams{MinTxnFee: txsigning.DefaultMinFee}
	}
	params, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return signersigning.PlannerNetworkParams{MinTxnFee: txsigning.DefaultMinFee}
	}
	return signersigning.PlannerNetworkParams{MinTxnFee: params.MinFee, ConsensusVersion: params.ConsensusVersion}
}
