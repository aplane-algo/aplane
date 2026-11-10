// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// validateTransactionBounds refuses a transaction the network could never
// accept, before anyone is asked to approve it: a validity window that is
// reversed or longer than a transaction may live, or a note past the absolute
// maximum. Bytes a caller supplies bypass the checks an SDK constructor makes,
// and without this the mistake surfaces only at submission, after an approval
// and a signature that bind those exact bytes.
//
// It is deliberately short. It is not node validation: confirmation also
// depends on chain state, and reproducing every consensus rule here would make
// the signer refuse valid transactions whenever it lagged a protocol upgrade.
// Every limit is read from the pinned consensus parameters fee planning already
// uses, never restated: a remembered constant is how a surcharge threshold gets
// mistaken for a maximum.
//
// Every position is checked, signed here or not: one member the network refuses
// fails the whole group.
func validateTransactionBounds(txns []types.Transaction) *ServiceError {
	params, ok := sdkconfig.Consensus[lsigresource.CurrentConsensusVersion]
	if !ok {
		return internal(fmt.Sprintf("SDK has no parameters for the compiled consensus contract %s", lsigresource.CurrentConsensusVersion))
	}
	for i, txn := range txns {
		if err := checkTransactionBounds(txn, params); err != nil {
			return badRequest(fmt.Sprintf("transaction %d: %v", i+1, err))
		}
	}
	return nil
}

func checkTransactionBounds(txn types.Transaction, params sdkconfig.ConsensusParams) error {
	if txn.LastValid < txn.FirstValid {
		return fmt.Errorf("last valid round %d is before first valid round %d, so it can never be valid", txn.LastValid, txn.FirstValid)
	}
	if life := uint64(txn.LastValid - txn.FirstValid); life > params.MaxTxnLife {
		return fmt.Errorf("validity window of %d rounds (%d to %d) is longer than the network's maximum of %d", life, txn.FirstValid, txn.LastValid, params.MaxTxnLife)
	}
	if len(txn.Note) > params.MaxAbsoluteTxnNoteBytes {
		return fmt.Errorf("note is %d bytes, above the network's maximum of %d", len(txn.Note), params.MaxAbsoluteTxnNoteBytes)
	}
	return nil
}
