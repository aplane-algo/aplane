// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	signutil "github.com/aplane-algo/aplane/internal/signing"
)

// rotatingDeps are the rotating flow's dependencies, shared by the HTTP
// endpoints and the stage table worker so both use one lock table and one
// set of open tables.
func (fs *Signer) rotatingDeps(ir *productruntime.Runtime) *signersigning.RotatingDeps {
	return &signersigning.RotatingDeps{
		Chain:  fs.rotatingChainReader(),
		Tables: ir.StageTables(),
		Locks:  &fs.rotatingLocks,
	}
}

// rotatingChainReader reads rotating accounts' authorizers from the node
// configured for each account's network. It is the one place the signer
// reads the chain.
func (fs *Signer) rotatingChainReader() chainread.Reader {
	makeClient := fs.makeAlgod
	if makeClient == nil {
		makeClient = signutil.CreateAlgodClient
	}
	return chainread.Reader{
		Resolver: fs.genesisHashResolver,
		AlgodConfig: func(network string) (*apconfig.AlgodNetworkConfig, error) {
			cfg := fs.ConfigSnapshot()
			return cfg.GetAlgodConfig(network)
		},
		MakeClient: makeClient,
	}
}
