// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txdesc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

type transactionDescriber func(txn types.Transaction) string

func describePaymentTx(txn types.Transaction) string {
	var desc strings.Builder
	amountAlgo := float64(txn.Amount) / 1_000_000.0
	desc.WriteString(fmt.Sprintf("Payment: %.6f ALGO", amountAlgo))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	desc.WriteString(fmt.Sprintf("\n  To:   %s", txn.Receiver.String()))

	if txn.Sender.String() == txn.Receiver.String() && txn.Amount == 0 {
		desc.WriteString("\n  [VALIDATION: 0 ALGO self-send]")
	}

	return desc.String()
}

func describeAssetTransferTx(txn types.Transaction) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("ASA Transfer: %d units of asset #%d", txn.AssetAmount, txn.XferAsset))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	desc.WriteString(fmt.Sprintf("\n  To:   %s", txn.AssetReceiver.String()))

	if !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender {
		desc.WriteString(fmt.Sprintf("\n  ⚠️  CLAWBACK FROM: %s", txn.AssetSender.String()))
	}

	if !txn.AssetCloseTo.IsZero() {
		desc.WriteString(fmt.Sprintf("\n  Close remainder to: %s", txn.AssetCloseTo.String()))
	}

	return desc.String()
}

func describeAssetConfigTx(txn types.Transaction) string {
	var desc strings.Builder
	if txn.ConfigAsset == 0 {
		desc.WriteString("Asset Creation")
		desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
		if txn.AssetParams.AssetName != "" {
			desc.WriteString(fmt.Sprintf("\n  Name: %s", txn.AssetParams.AssetName))
		}
		if txn.AssetParams.UnitName != "" {
			desc.WriteString(fmt.Sprintf("\n  Unit: %s", txn.AssetParams.UnitName))
		}
		desc.WriteString(fmt.Sprintf("\n  Total: %d", txn.AssetParams.Total))
		desc.WriteString(fmt.Sprintf("\n  Decimals: %d", txn.AssetParams.Decimals))
		desc.WriteString(fmt.Sprintf("\n  Default Frozen: %t", txn.AssetParams.DefaultFrozen))
		desc.WriteString(fmt.Sprintf("\n  Manager: %s", formatAuthorityAddress(txn.AssetParams.Manager)))
		desc.WriteString(fmt.Sprintf("\n  Reserve: %s", formatAuthorityAddress(txn.AssetParams.Reserve)))
		desc.WriteString(fmt.Sprintf("\n  Freeze: %s", formatAuthorityAddress(txn.AssetParams.Freeze)))
		desc.WriteString(fmt.Sprintf("\n  Clawback: %s", formatAuthorityAddress(txn.AssetParams.Clawback)))
		if txn.AssetParams.URL != "" {
			desc.WriteString(fmt.Sprintf("\n  URL: %s", txn.AssetParams.URL))
		}
		if !isZeroMetadataHash(txn.AssetParams.MetadataHash) {
			desc.WriteString(fmt.Sprintf("\n  Metadata Hash: %s", hex.EncodeToString(txn.AssetParams.MetadataHash[:])))
		}
	} else if txn.AssetParams.IsZero() {
		desc.WriteString(fmt.Sprintf("Asset Destroy: asset #%d", txn.ConfigAsset))
		desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	} else {
		desc.WriteString(fmt.Sprintf("Asset Reconfiguration: asset #%d", txn.ConfigAsset))
		desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
		desc.WriteString(fmt.Sprintf("\n  Manager: %s", formatAuthorityAddress(txn.AssetParams.Manager)))
		desc.WriteString(fmt.Sprintf("\n  Reserve: %s", formatAuthorityAddress(txn.AssetParams.Reserve)))
		desc.WriteString(fmt.Sprintf("\n  Freeze: %s", formatAuthorityAddress(txn.AssetParams.Freeze)))
		desc.WriteString(fmt.Sprintf("\n  Clawback: %s", formatAuthorityAddress(txn.AssetParams.Clawback)))
	}
	return desc.String()
}

func describeAssetFreezeTx(txn types.Transaction) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Asset Freeze: asset #%d", txn.FreezeAsset))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	desc.WriteString(fmt.Sprintf("\n  Account: %s", txn.FreezeAccount.String()))
	if txn.AssetFrozen {
		desc.WriteString("\n  Action: FREEZE")
	} else {
		desc.WriteString("\n  Action: UNFREEZE")
	}
	return desc.String()
}

func describeApplicationCallTx(txn types.Transaction) string {
	var desc strings.Builder
	if txn.ApplicationID == 0 {
		desc.WriteString(fmt.Sprintf("App Create (%s)", appOnCompletionLabel(txn.OnCompletion)))
	} else {
		desc.WriteString(fmt.Sprintf("App Call: #%d (%s)", txn.ApplicationID, appOnCompletionLabel(txn.OnCompletion)))
	}
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	appendAppProgramDetails(&desc, txn)

	if len(txn.ApplicationArgs) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Args: %d argument(s)", len(txn.ApplicationArgs)))
		for i, arg := range txn.ApplicationArgs {
			desc.WriteString(fmt.Sprintf("\n    [%d]: %s", i, formatAppArg(i, arg)))
		}
	}

	if len(txn.Accounts) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Accounts: %d", len(txn.Accounts)))
		for i, addr := range txn.Accounts {
			desc.WriteString(fmt.Sprintf("\n    [%d]: %s", i, addr.String()))
		}
	}

	if len(txn.ForeignApps) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Foreign Apps: %d", len(txn.ForeignApps)))
		for i, appID := range txn.ForeignApps {
			desc.WriteString(fmt.Sprintf("\n    [%d]: %d", i, appID))
		}
	}

	if len(txn.ForeignAssets) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Foreign Assets: %d", len(txn.ForeignAssets)))
		for i, assetID := range txn.ForeignAssets {
			desc.WriteString(fmt.Sprintf("\n    [%d]: %d", i, assetID))
		}
	}

	if len(txn.BoxReferences) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Boxes: %d", len(txn.BoxReferences)))
		for i, ref := range txn.BoxReferences {
			desc.WriteString(fmt.Sprintf("\n    [%d]: app %s / %s", i, resolveBoxAppRef(txn, ref), formatBoxName(ref.Name)))
		}
	}

	return desc.String()
}

func appOnCompletionLabel(onComp types.OnCompletion) string {
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

func formatAppArg(index int, arg []byte) string {
	_ = index
	return formatOpaqueBytes(arg)
}

func formatBoxName(name []byte) string {
	return formatOpaqueBytes(name)
}

func resolveBoxAppRef(txn types.Transaction, ref types.BoxReference) string {
	if ref.ForeignAppIdx == 0 {
		return fmt.Sprintf("%d", txn.ApplicationID)
	}
	idx := int(ref.ForeignAppIdx - 1)
	if idx >= 0 && idx < len(txn.ForeignApps) {
		return fmt.Sprintf("%d", txn.ForeignApps[idx])
	}
	return fmt.Sprintf("?idx=%d", ref.ForeignAppIdx)
}

func describeKeyRegistrationTx(txn types.Transaction) string {
	var desc strings.Builder

	emptyVotePK := types.VotePK{}
	emptySelectionPK := types.VRFPK{}
	if txn.VotePK == emptyVotePK && txn.SelectionPK == emptySelectionPK {
		if txn.Nonparticipation {
			desc.WriteString("Key Registration: Go NONPARTICIPATING")
		} else {
			desc.WriteString("Key Registration: Go OFFLINE")
		}
	} else {
		desc.WriteString("Key Registration: Go ONLINE")
		desc.WriteString(fmt.Sprintf("\n  VotePK: %s...", hex.EncodeToString(txn.VotePK[:])[:16]))
		desc.WriteString(fmt.Sprintf("\n  SelectionPK: %s...", hex.EncodeToString(txn.SelectionPK[:])[:16]))
		desc.WriteString(fmt.Sprintf("\n  VoteFirst: %d", txn.VoteFirst))
		desc.WriteString(fmt.Sprintf("\n  VoteLast: %d", txn.VoteLast))
		desc.WriteString(fmt.Sprintf("\n  VoteKeyDilution: %d", txn.VoteKeyDilution))
		if !isZeroStateProofKey(txn.StateProofPK) {
			desc.WriteString(fmt.Sprintf("\n  StateProofPK: %s...", hex.EncodeToString(txn.StateProofPK[:])[:16]))
		}
		if txn.Nonparticipation {
			desc.WriteString("\n  Nonparticipation: true")
		}
	}
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))

	return desc.String()
}

func describeUnknownTx(txn types.Transaction) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Transaction Type: %s", txn.Type))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	return desc.String()
}

// appendCommonFields adds fee, network identity, note, close remainder, rekey, group, and round info.
func appendCommonFields(desc *strings.Builder, txn types.Transaction, resolver apconfig.GenesisHashNetworkResolver) {
	feeAlgo := float64(txn.Fee) / 1_000_000.0
	fmt.Fprintf(desc, "\n  Fee: %.6f ALGO", feeAlgo)

	if network, ok := resolver.NetworkForGenesisHashBytes(txn.GenesisHash[:]); ok {
		fmt.Fprintf(desc, "\n  Network: %s", network)
	}
	if txn.GenesisID != "" {
		fmt.Fprintf(desc, "\n  GenesisID: %s", txn.GenesisID)
	}

	if len(txn.Note) > 0 {
		fmt.Fprintf(desc, "\n  Note: %s", formatOpaqueBytes(txn.Note))
	}

	if !txn.CloseRemainderTo.IsZero() {
		fmt.Fprintf(desc, "\n  Close remainder to: %s", txn.CloseRemainderTo.String())
	}

	if !txn.RekeyTo.IsZero() {
		fmt.Fprintf(desc, "\n  ⚠️  REKEY TO: %s", txn.RekeyTo.String())
	}

	emptyGroup := types.Digest{}
	if txn.Group != emptyGroup {
		fmt.Fprintf(desc, "\n  Group: %s", hex.EncodeToString(txn.Group[:]))
		desc.WriteString("\n  [Part of atomic transaction group]")
	}
}

// transactionDescribers maps transaction types to their describers
var transactionDescribers = map[string]transactionDescriber{
	string(types.PaymentTx):         describePaymentTx,
	string(types.AssetTransferTx):   describeAssetTransferTx,
	string(types.AssetConfigTx):     describeAssetConfigTx,
	string(types.AssetFreezeTx):     describeAssetFreezeTx,
	string(types.ApplicationCallTx): describeApplicationCallTx,
	string(types.KeyRegistrationTx): describeKeyRegistrationTx,
}

// DescribeHexWithResolver creates trustless human-readable
// transaction descriptions derived directly from transaction bytes.
func DescribeHexWithResolver(txnBytesHex string, resolver apconfig.GenesisHashNetworkResolver) string {
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

	return DescribeTxnWithResolver(txn, resolver)
}

// DescribeTxn creates a human-readable transaction description
// from a decoded transaction object. Use this when you have a modified transaction
// (e.g., after fee adjustments) to show the actual values that will be signed.
func DescribeTxn(txn types.Transaction) string {
	return DescribeTxnWithResolver(txn, apconfig.DefaultGenesisHashNetworkResolver())
}

func DescribeTxnWithResolver(txn types.Transaction, resolver apconfig.GenesisHashNetworkResolver) string {
	describer, exists := transactionDescribers[string(txn.Type)]
	if !exists {
		describer = describeUnknownTx
	}

	var builder strings.Builder
	builder.WriteString(describer(txn))
	appendCommonFields(&builder, txn, resolver)

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

func formatOpaqueBytes(data []byte) string {
	if len(data) == 0 {
		return `""`
	}
	if isPrintable(data) {
		if len(data) <= 64 {
			return strconv.Quote(string(data))
		}
		sum := sha256.Sum256(data)
		return fmt.Sprintf("%s (%d bytes, sha256=%s)", strconv.Quote(string(data[:64]))+"...", len(data), hex.EncodeToString(sum[:]))
	}
	if len(data) <= 32 {
		return fmt.Sprintf("0x%s", hex.EncodeToString(data))
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("0x%s... (%d bytes, sha256=%s)", hex.EncodeToString(data[:32]), len(data), hex.EncodeToString(sum[:]))
}

func appendAppProgramDetails(desc *strings.Builder, txn types.Transaction) {
	if len(txn.ApprovalProgram) > 0 {
		approvalHash := sha256.Sum256(txn.ApprovalProgram)
		fmt.Fprintf(desc, "\n  Approval Program: %d bytes, sha256=%s",
			len(txn.ApprovalProgram), hex.EncodeToString(approvalHash[:]))
	}
	if len(txn.ClearStateProgram) > 0 {
		clearHash := sha256.Sum256(txn.ClearStateProgram)
		fmt.Fprintf(desc, "\n  Clear Program: %d bytes, sha256=%s",
			len(txn.ClearStateProgram), hex.EncodeToString(clearHash[:]))
	}

	if txn.GlobalStateSchema.NumUint > 0 || txn.GlobalStateSchema.NumByteSlice > 0 {
		fmt.Fprintf(desc, "\n  Global Schema: %d uint, %d bytes",
			txn.GlobalStateSchema.NumUint, txn.GlobalStateSchema.NumByteSlice)
	}
	if txn.LocalStateSchema.NumUint > 0 || txn.LocalStateSchema.NumByteSlice > 0 {
		fmt.Fprintf(desc, "\n  Local Schema: %d uint, %d bytes",
			txn.LocalStateSchema.NumUint, txn.LocalStateSchema.NumByteSlice)
	}
	if txn.ExtraProgramPages > 0 {
		fmt.Fprintf(desc, "\n  Extra Program Pages: %d", txn.ExtraProgramPages)
	}
}

func formatAuthorityAddress(addr types.Address) string {
	if addr.IsZero() {
		return "(zero address / disabled)"
	}
	return addr.String()
}

func isZeroMetadataHash(hash [32]byte) bool {
	var zero [32]byte
	return hash == zero
}

func isZeroStateProofKey(key types.MerkleVerifier) bool {
	var zero types.MerkleVerifier
	return key == zero
}
