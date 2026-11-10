// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

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
//
// Every limit is read from the compiled consensus profile fee planning uses,
// never restated: a remembered constant is how a surcharge threshold gets
// mistaken for a maximum. That profile is one pinned version for every network,
// so these are refusals under it. The versions the signer accepts agree on both
// limits, which a test holds; a protocol change to either needs the pin moved.
//
// Every position is checked, signed here or not: one member the network refuses
// fails the whole group.
func validateTransactionBounds(txns []types.Transaction) *ServiceError {
	profile, err := lsigresource.CurrentConsensus()
	if err != nil {
		return internal(fmt.Sprintf("load compiled consensus contract: %v", err))
	}
	for i := range txns {
		if err := checkTransactionBounds(&txns[i], profile); err != nil {
			return badRequest(fmt.Sprintf("transaction %d: %v", i+1, err))
		}
	}
	return nil
}

func checkTransactionBounds(txn *types.Transaction, profile lsigresource.ConsensusProfile) error {
	if txn.LastValid < txn.FirstValid {
		return fmt.Errorf("last valid round %d is before first valid round %d, so it can never be valid", txn.LastValid, txn.FirstValid)
	}
	if life := uint64(txn.LastValid - txn.FirstValid); life > profile.MaxTxnLife {
		return fmt.Errorf("validity window of %d rounds (%d to %d) is longer than the network's maximum of %d", life, txn.FirstValid, txn.LastValid, profile.MaxTxnLife)
	}
	if size := uint64(len(txn.Note)); size > profile.MaxAbsoluteTxnNoteBytes {
		return fmt.Errorf("note is %d bytes, above the network's maximum of %d", size, profile.MaxAbsoluteTxnNoteBytes)
	}
	return nil
}
