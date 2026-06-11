// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/txdesc"
)

func (fs *Signer) generateTransactionDescription(txnBytesHex string) string {
	return txdesc.DescribeHexWithResolver(txnBytesHex, fs.genesisHashResolver())
}

func (fs *Signer) generateTransactionDescriptionFromTxn(txn types.Transaction) string {
	return txdesc.DescribeTxnWithResolver(txn, fs.genesisHashResolver())
}
