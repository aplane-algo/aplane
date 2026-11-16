// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/txdesc"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

func (fs *Signer) generateTransactionDescriptionFromTxn(txn types.Transaction) txnreview.Details {
	return txdesc.DetailTxnWithResolver(txn, fs.genesisHashResolver())
}
