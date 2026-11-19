// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/addressbook"
	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

// formatTransactionSummary creates a human-readable summary of a transaction
// with shortened addresses.
func formatTransactionSummary(txn types.Transaction) string {
	senderFmt := addressbook.FormatAddressShort(txn.Sender.String())

	switch txn.Type {
	case types.PaymentTx:
		receiverFmt := addressbook.FormatAddressShort(txn.Receiver.String())
		return fmt.Sprintf("Payment: %s → %s (%s ALGO)",
			senderFmt, receiverFmt, asaset.FormatFixed(uint64(txn.Amount), 6))

	case types.AssetTransferTx:
		receiverFmt := addressbook.FormatAddressShort(txn.AssetReceiver.String())
		return fmt.Sprintf("Asset Transfer: %s → %s (Asset %d, Amount %d)",
			senderFmt, receiverFmt, txn.XferAsset, txn.AssetAmount)

	case types.AssetConfigTx:
		if txn.ConfigAsset == 0 {
			return fmt.Sprintf("Asset Create: %s (creating new asset)", senderFmt)
		}
		return fmt.Sprintf("Asset Config: %s (modifying asset %d)", senderFmt, txn.ConfigAsset)

	case types.AssetFreezeTx:
		targetFmt := addressbook.FormatAddressShort(txn.FreezeAccount.String())
		return fmt.Sprintf("Asset Freeze: %s (asset %d, target %s)",
			senderFmt, txn.FreezeAsset, targetFmt)

	case types.ApplicationCallTx:
		return fmt.Sprintf("App Call: %s → App %d (%s, %d arg(s))",
			senderFmt, txn.ApplicationID, txnreview.OnCompletionLabel(txn.OnCompletion), len(txn.ApplicationArgs))

	case types.KeyRegistrationTx:
		// The describer's own rule for offline, so this summary and the
		// review of the same bytes agree.
		if txnreview.IsOfflineKeyReg(txn) {
			if txn.Nonparticipation {
				return fmt.Sprintf("Key Registration: %s (NONPARTICIPATING, cannot be undone)", senderFmt)
			}
			return fmt.Sprintf("Key Registration: %s (offline)", senderFmt)
		}
		return fmt.Sprintf("Key Registration: %s (online)", senderFmt)

	default:
		return fmt.Sprintf("Transaction: %s (type %s)", senderFmt, txn.Type)
	}
}
