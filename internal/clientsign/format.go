// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/addressbook"
	"github.com/aplane-algo/aplane/internal/cache"
)

// FormatTransactionSummary creates a human-readable summary of a transaction
// If aliasCache is nil, uses short address format. If provided, shows aliases.
func FormatTransactionSummary(txn types.Transaction, aliasCache *cache.AliasCache) string {
	sender := txn.Sender.String()
	senderFmt := formatAddress(sender, aliasCache)

	switch txn.Type {
	case types.PaymentTx:
		receiver := txn.Receiver.String()
		receiverFmt := formatAddress(receiver, aliasCache)
		amount := float64(txn.Amount) / 1000000.0
		return fmt.Sprintf("Payment: %s → %s (%.6f ALGO)",
			senderFmt, receiverFmt, amount)

	case types.AssetTransferTx:
		receiver := txn.AssetReceiver.String()
		receiverFmt := formatAddress(receiver, aliasCache)
		return fmt.Sprintf("Asset Transfer: %s → %s (Asset %d, Amount %d)",
			senderFmt, receiverFmt, txn.XferAsset, txn.AssetAmount)

	case types.AssetConfigTx:
		if txn.ConfigAsset == 0 {
			return fmt.Sprintf("Asset Create: %s (creating new asset)", senderFmt)
		}
		return fmt.Sprintf("Asset Config: %s (modifying asset %d)", senderFmt, txn.ConfigAsset)

	case types.AssetFreezeTx:
		target := txn.FreezeAccount.String()
		targetFmt := formatAddress(target, aliasCache)
		return fmt.Sprintf("Asset Freeze: %s (asset %d, target %s)",
			senderFmt, txn.FreezeAsset, targetFmt)

	case types.ApplicationCallTx:
		return fmt.Sprintf("App Call: %s → App %d (%s, %d arg(s))",
			senderFmt, txn.ApplicationID, onCompletionLabel(txn.OnCompletion), len(txn.ApplicationArgs))

	case types.KeyRegistrationTx:
		// Check if vote key is empty (all zeros)
		emptyVotePK := true
		for _, b := range txn.VotePK {
			if b != 0 {
				emptyVotePK = false
				break
			}
		}
		if emptyVotePK {
			return fmt.Sprintf("Key Registration: %s (offline)", senderFmt)
		}
		return fmt.Sprintf("Key Registration: %s (online)", senderFmt)

	default:
		return fmt.Sprintf("Transaction: %s (type %s)", senderFmt, txn.Type)
	}
}

// formatAddress formats an address with alias if available, otherwise shortened.
func formatAddress(addr string, aliasCache *cache.AliasCache) string {
	return addressbook.FormatAddressWithAlias(addr, aliasCache)
}

func onCompletionLabel(onComp types.OnCompletion) string {
	switch onComp {
	case types.NoOpOC:
		return "NoOp"
	case types.OptInOC:
		return "OptIn"
	case types.CloseOutOC:
		return "CloseOut"
	case types.ClearStateOC:
		return "ClearState"
	case types.UpdateApplicationOC:
		return "Update"
	case types.DeleteApplicationOC:
		return "Delete"
	default:
		return fmt.Sprintf("OnCompletion(%d)", onComp)
	}
}
