// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package txdesc describes a transaction for the signer: it gives the shared
// describer in internal/txnreview what the signer knows of the transaction's
// chain, the network's name and the node's ASA set. The text itself is built
// there, where apshell's review of a plugin group builds it too.
package txdesc

import (
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

// DetailTxnWithResolver describes txn as data, naming its network through
// resolver.
func DetailTxnWithResolver(txn types.Transaction, resolver apconfig.GenesisHashNetworkResolver) txnreview.Details {
	network, _ := resolver.NetworkForGenesisHashBytes(txn.GenesisHash[:])
	return txnreview.Detail(txn, txnreview.View{Network: network})
}

// DetailTxnInContext describes txn in a node's policy context: the network
// is the one the context maps the transaction's chain to, and an asset the
// context's ASA set knows is shown in its display units beside its base
// units. An approval prompt is built from the context its signing request
// captured, so a reload while it waits does not change what it says.
func DetailTxnInContext(txn types.Transaction, ctx *policycontext.Context) txnreview.Details {
	network, _ := ctx.Network(asaset.GenesisHash(txn.GenesisHash))
	return txnreview.Detail(txn, txnreview.View{Network: network, Assets: ctx.Assets()})
}
