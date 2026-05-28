// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "github.com/algorand/go-algorand-sdk/v2/types"

// SelfNoOpTransferMaxFeeMicroAlgos is intentionally tight; higher-fee no-op
// transfers should fall back to the default approval path.
const SelfNoOpTransferMaxFeeMicroAlgos uint64 = 1_000

// MatchesSelfNoOpTransferAutoApproval reports whether txn is a standalone
// self-transfer no-op eligible for the built-in auto-approval rule. Group,
// passthrough, foreign, and dummy context is checked by the signing service.
func MatchesSelfNoOpTransferAutoApproval(txn types.Transaction) bool {
	if !matchesSelfNoOpCommon(txn) {
		return false
	}

	switch txn.Type {
	case types.PaymentTx:
		return matchesAlgoSelfNoOp(txn)
	case types.AssetTransferTx:
		return matchesASASelfNoOp(txn)
	default:
		return false
	}
}

func matchesSelfNoOpCommon(txn types.Transaction) bool {
	if txn.Sender.IsZero() {
		return false
	}
	if uint64(txn.Fee) > SelfNoOpTransferMaxFeeMicroAlgos {
		return false
	}
	if !txn.RekeyTo.IsZero() || !txn.CloseRemainderTo.IsZero() {
		return false
	}
	if txn.Group != (types.Digest{}) {
		return false
	}
	if len(txn.Note) > 0 || txn.Lease != ([32]byte{}) {
		return false
	}
	return true
}

func matchesAlgoSelfNoOp(txn types.Transaction) bool {
	return txn.Receiver == txn.Sender && txn.Amount == 0
}

func matchesASASelfNoOp(txn types.Transaction) bool {
	return txn.XferAsset != 0 &&
		txn.AssetReceiver == txn.Sender &&
		txn.AssetAmount == 0 &&
		txn.AssetSender.IsZero() &&
		txn.AssetCloseTo.IsZero()
}
