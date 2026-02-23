// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/util"
)

type TransactionDescriber func(txn types.Transaction) string

func describePaymentTx(txn types.Transaction) string {
	var desc strings.Builder
	amountAlgo := float64(txn.Amount) / 1_000_000.0
	desc.WriteString(fmt.Sprintf("Payment: %.6f ALGO", amountAlgo))
	desc.WriteString(fmt.Sprintf("\n  From: %s", util.FormatAddressShort(txn.Sender.String())))
	desc.WriteString(fmt.Sprintf("\n  To:   %s", util.FormatAddressShort(txn.Receiver.String())))

	if txn.Sender.String() == txn.Receiver.String() && txn.Amount == 0 {
		desc.WriteString("\n  [VALIDATION: 0 ALGO self-send]")
	}

	return desc.String()
}

func describeAssetTransferTx(txn types.Transaction) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("ASA Transfer: %d units of asset #%d", txn.AssetAmount, txn.XferAsset))
	desc.WriteString(fmt.Sprintf("\n  From: %s", util.FormatAddressShort(txn.Sender.String())))
	desc.WriteString(fmt.Sprintf("\n  To:   %s", util.FormatAddressShort(txn.AssetReceiver.String())))

	if !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender {
		desc.WriteString(fmt.Sprintf("\n  ⚠️  CLAWBACK FROM: %s", util.FormatAddressShort(txn.AssetSender.String())))
	}

	if !txn.AssetCloseTo.IsZero() {
		desc.WriteString(fmt.Sprintf("\n  Close remainder to: %s", util.FormatAddressShort(txn.AssetCloseTo.String())))
	}

	return desc.String()
}

func describeAssetConfigTx(txn types.Transaction) string {
	var desc strings.Builder
	if txn.ConfigAsset == 0 {
		desc.WriteString("Asset Creation")
		if txn.AssetParams.AssetName != "" {
			desc.WriteString(fmt.Sprintf("\n  Name: %s", txn.AssetParams.AssetName))
		}
		if txn.AssetParams.UnitName != "" {
			desc.WriteString(fmt.Sprintf("\n  Unit: %s", txn.AssetParams.UnitName))
		}
		desc.WriteString(fmt.Sprintf("\n  Total: %d", txn.AssetParams.Total))
		desc.WriteString(fmt.Sprintf("\n  Decimals: %d", txn.AssetParams.Decimals))
	} else {
		desc.WriteString(fmt.Sprintf("Asset Reconfiguration: asset #%d", txn.ConfigAsset))
	}
	return desc.String()
}

func describeAssetFreezeTx(txn types.Transaction) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Asset Freeze: asset #%d", txn.FreezeAsset))
	desc.WriteString(fmt.Sprintf("\n  Account: %s", util.FormatAddressShort(txn.FreezeAccount.String())))
	if txn.AssetFrozen {
		desc.WriteString("\n  Action: FREEZE")
	} else {
		desc.WriteString("\n  Action: UNFREEZE")
	}
	return desc.String()
}

func describeApplicationCallTx(txn types.Transaction) string {
	var desc strings.Builder

	switch txn.OnCompletion {
	case types.NoOpOC:
		desc.WriteString(fmt.Sprintf("App Call: #%d (NoOp)", txn.ApplicationID))
	case types.OptInOC:
		desc.WriteString(fmt.Sprintf("App OptIn: #%d", txn.ApplicationID))
	case types.CloseOutOC:
		desc.WriteString(fmt.Sprintf("App CloseOut: #%d", txn.ApplicationID))
	case types.ClearStateOC:
		desc.WriteString(fmt.Sprintf("App ClearState: #%d", txn.ApplicationID))
	case types.UpdateApplicationOC:
		desc.WriteString(fmt.Sprintf("App Update: #%d", txn.ApplicationID))
	case types.DeleteApplicationOC:
		desc.WriteString(fmt.Sprintf("App Delete: #%d", txn.ApplicationID))
	default:
		desc.WriteString(fmt.Sprintf("App Call: #%d", txn.ApplicationID))
	}

	if len(txn.ApplicationArgs) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Args: %d argument(s)", len(txn.ApplicationArgs)))
		for i, arg := range txn.ApplicationArgs {
			if i >= 3 {
				desc.WriteString(fmt.Sprintf("\n    ... (%d more args)", len(txn.ApplicationArgs)-3))
				break
			}
			if isPrintable(arg) {
				desc.WriteString(fmt.Sprintf("\n    [%d]: %s", i, string(arg)))
			} else {
				desc.WriteString(fmt.Sprintf("\n    [%d]: 0x%s", i, hex.EncodeToString(arg)))
			}
		}
	}

	if len(txn.Accounts) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Accounts: %d", len(txn.Accounts)))
		for i, addr := range txn.Accounts {
			if i >= 3 {
				desc.WriteString(fmt.Sprintf("\n    ... (%d more)", len(txn.Accounts)-3))
				break
			}
			desc.WriteString(fmt.Sprintf("\n    [%d]: %s", i, util.FormatAddressShort(addr.String())))
		}
	}

	if len(txn.ForeignApps) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Foreign Apps: %v", txn.ForeignApps))
	}

	if len(txn.ForeignAssets) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Foreign Assets: %v", txn.ForeignAssets))
	}

	return desc.String()
}

func describeKeyRegistrationTx(txn types.Transaction) string {
	var desc strings.Builder

	emptyVotePK := types.VotePK{}
	emptySelectionPK := types.VRFPK{}
	if txn.VotePK == emptyVotePK && txn.SelectionPK == emptySelectionPK {
		desc.WriteString("Key Registration: Go OFFLINE")
	} else {
		desc.WriteString("Key Registration: Go ONLINE")
		desc.WriteString(fmt.Sprintf("\n  VotePK: %s...", hex.EncodeToString(txn.VotePK[:])[:16]))
		desc.WriteString(fmt.Sprintf("\n  SelectionPK: %s...", hex.EncodeToString(txn.SelectionPK[:])[:16]))
		desc.WriteString(fmt.Sprintf("\n  VoteFirst: %d", txn.VoteFirst))
		desc.WriteString(fmt.Sprintf("\n  VoteLast: %d", txn.VoteLast))
	}

	return desc.String()
}

func describeUnknownTx(txn types.Transaction) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Transaction Type: %s", txn.Type))
	desc.WriteString(fmt.Sprintf("\n  From: %s", util.FormatAddressShort(txn.Sender.String())))
	return desc.String()
}

// appendCommonFields adds fee, note, close remainder, rekey, group, and round info
func appendCommonFields(desc *strings.Builder, txn types.Transaction) {
	feeAlgo := float64(txn.Fee) / 1_000_000.0
	fmt.Fprintf(desc, "\n  Fee: %.6f ALGO", feeAlgo)

	if txn.GenesisID != "" {
		fmt.Fprintf(desc, "\n  Network: %s", txn.GenesisID)
	}
	if len(txn.GenesisHash) > 0 {
		fmt.Fprintf(desc, "\n  GenHash: %s...", hex.EncodeToString(txn.GenesisHash[:])[:8])
	}

	if len(txn.Note) > 0 {
		if isPrintable(txn.Note) {
			fmt.Fprintf(desc, "\n  Note: %s", string(txn.Note))
		} else {
			fmt.Fprintf(desc, "\n  Note (hex): %s", hex.EncodeToString(txn.Note))
		}
	}

	if !txn.CloseRemainderTo.IsZero() {
		fmt.Fprintf(desc, "\n  Close remainder to: %s", util.FormatAddressShort(txn.CloseRemainderTo.String()))
	}

	if !txn.RekeyTo.IsZero() {
		fmt.Fprintf(desc, "\n  ⚠️  REKEY TO: %s", util.FormatAddressShort(txn.RekeyTo.String()))
	}

	emptyGroup := types.Digest{}
	if txn.Group != emptyGroup {
		fmt.Fprintf(desc, "\n  Group: %s...", hex.EncodeToString(txn.Group[:])[:16])
		desc.WriteString("\n  [Part of atomic transaction group]")
	}
}

// transactionDescribers maps transaction types to their describers
var transactionDescribers = map[string]TransactionDescriber{
	string(types.PaymentTx):         describePaymentTx,
	string(types.AssetTransferTx):   describeAssetTransferTx,
	string(types.AssetConfigTx):     describeAssetConfigTx,
	string(types.AssetFreezeTx):     describeAssetFreezeTx,
	string(types.ApplicationCallTx): describeApplicationCallTx,
	string(types.KeyRegistrationTx): describeKeyRegistrationTx,
}

// generateTransactionDescription creates trustless human-readable transaction description
// derived directly from transaction bytes. Uses plugin-friendly architecture where each
// transaction type has its own describer in transactionDescribers map.
func generateTransactionDescription(txnBytesHex string) string {
	if txnBytesHex == "" {
		return ""
	}

	txnBytes, err := hex.DecodeString(txnBytesHex)
	if err != nil {
		return fmt.Sprintf("[Error decoding transaction: %v]", err)
	}

	if len(txnBytes) > 2 && txnBytes[0] == 'T' && txnBytes[1] == 'X' {
		txnBytes = txnBytes[2:]
	}

	var txn types.Transaction
	if err := msgpack.Decode(txnBytes, &txn); err != nil {
		return fmt.Sprintf("[Error decoding transaction structure: %v]", err)
	}

	return generateTransactionDescriptionFromTxn(txn)
}

// generateTransactionDescriptionFromTxn creates a human-readable transaction description
// from a decoded transaction object. Use this when you have a modified transaction
// (e.g., after fee adjustments) to show the actual values that will be signed.
func generateTransactionDescriptionFromTxn(txn types.Transaction) string {
	describer, exists := transactionDescribers[string(txn.Type)]
	if !exists {
		describer = describeUnknownTx
	}

	var builder strings.Builder
	builder.WriteString(describer(txn))
	appendCommonFields(&builder, txn)

	return builder.String()
}

func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
