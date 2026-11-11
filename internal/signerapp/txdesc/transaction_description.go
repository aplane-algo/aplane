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

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/termsafe"
)

type transactionDescriber func(txn types.Transaction, chain chainView) string

// chainView is what a description knows of the transaction's chain: the
// network token that names it, and, with a policy context, the node's ASA
// set, which labels assets.
type chainView struct {
	network string
	ctx     *policycontext.Context
}

// asset returns what the node's ASA set knows of asset id on the
// transaction's chain.
func (v chainView) asset(genesis types.Digest, id uint64) (asaset.Asset, bool) {
	if v.ctx == nil {
		return asaset.Asset{}, false
	}
	return v.ctx.Assets().Lookup(asaset.Identity{Genesis: asaset.GenesisHash(genesis), AssetID: id})
}

// assetRef names asset id, with its unit name when the node's set knows it.
func (v chainView) assetRef(genesis types.Digest, id uint64) string {
	if a, ok := v.asset(genesis, id); ok {
		if unit := asaset.Printable(a.UnitName); unit != "" {
			return fmt.Sprintf("asset #%d (%s)", id, unit)
		}
	}
	return fmt.Sprintf("asset #%d", id)
}

func describePaymentTx(txn types.Transaction, chain chainView) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Payment: %s ALGO", asaset.FormatFixed(uint64(txn.Amount), 6)))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	desc.WriteString(fmt.Sprintf("\n  To:   %s", txn.Receiver.String()))

	if txn.Sender.String() == txn.Receiver.String() && txn.Amount == 0 {
		desc.WriteString("\n  [VALIDATION: 0 ALGO self-send]")
	}

	return desc.String()
}

func describeAssetTransferTx(txn types.Transaction, chain chainView) string {
	var desc strings.Builder
	amount := fmt.Sprintf("%d base units", txn.AssetAmount)
	asset, known := chain.asset(txn.GenesisHash, uint64(txn.XferAsset))
	if known {
		amount = asset.Display(txn.AssetAmount)
	}
	desc.WriteString(fmt.Sprintf("ASA Transfer: %s, asset #%d", amount, txn.XferAsset))
	if chain.network != "" {
		desc.WriteString(", " + chain.network)
	}
	if !known && chain.ctx != nil {
		desc.WriteString("\n  Not in this node's ASA set")
	}
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

func describeAssetConfigTx(txn types.Transaction, chain chainView) string {
	var desc strings.Builder
	if txn.ConfigAsset == 0 {
		desc.WriteString("Asset Creation")
		desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
		if txn.AssetParams.AssetName != "" {
			desc.WriteString(fmt.Sprintf("\n  Name: %s", termsafe.Line(txn.AssetParams.AssetName)))
		}
		if txn.AssetParams.UnitName != "" {
			desc.WriteString(fmt.Sprintf("\n  Unit: %s", termsafe.Line(txn.AssetParams.UnitName)))
		}
		desc.WriteString(fmt.Sprintf("\n  Total: %d", txn.AssetParams.Total))
		desc.WriteString(fmt.Sprintf("\n  Decimals: %d", txn.AssetParams.Decimals))
		desc.WriteString(fmt.Sprintf("\n  Default Frozen: %t", txn.AssetParams.DefaultFrozen))
		desc.WriteString(fmt.Sprintf("\n  Manager: %s", formatAuthorityAddress(txn.AssetParams.Manager)))
		desc.WriteString(fmt.Sprintf("\n  Reserve: %s", formatAuthorityAddress(txn.AssetParams.Reserve)))
		desc.WriteString(fmt.Sprintf("\n  Freeze: %s", formatAuthorityAddress(txn.AssetParams.Freeze)))
		desc.WriteString(fmt.Sprintf("\n  Clawback: %s", formatAuthorityAddress(txn.AssetParams.Clawback)))
		if txn.AssetParams.URL != "" {
			desc.WriteString(fmt.Sprintf("\n  URL: %s", termsafe.Line(txn.AssetParams.URL)))
		}
		if !isZeroMetadataHash(txn.AssetParams.MetadataHash) {
			desc.WriteString(fmt.Sprintf("\n  Metadata Hash: %s", hex.EncodeToString(txn.AssetParams.MetadataHash[:])))
		}
	} else if txn.AssetParams.IsZero() {
		desc.WriteString("Asset Destroy: " + chain.assetRef(txn.GenesisHash, uint64(txn.ConfigAsset)))
		desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	} else {
		desc.WriteString("Asset Reconfiguration: " + chain.assetRef(txn.GenesisHash, uint64(txn.ConfigAsset)))
		desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
		desc.WriteString(fmt.Sprintf("\n  Manager: %s", formatAuthorityAddress(txn.AssetParams.Manager)))
		desc.WriteString(fmt.Sprintf("\n  Reserve: %s", formatAuthorityAddress(txn.AssetParams.Reserve)))
		desc.WriteString(fmt.Sprintf("\n  Freeze: %s", formatAuthorityAddress(txn.AssetParams.Freeze)))
		desc.WriteString(fmt.Sprintf("\n  Clawback: %s", formatAuthorityAddress(txn.AssetParams.Clawback)))
	}
	return desc.String()
}

func describeAssetFreezeTx(txn types.Transaction, chain chainView) string {
	var desc strings.Builder
	desc.WriteString("Asset Freeze: " + chain.assetRef(txn.GenesisHash, uint64(txn.FreezeAsset)))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	desc.WriteString(fmt.Sprintf("\n  Account: %s", txn.FreezeAccount.String()))
	if txn.AssetFrozen {
		desc.WriteString("\n  Action: FREEZE")
	} else {
		desc.WriteString("\n  Action: UNFREEZE")
	}
	return desc.String()
}

func describeApplicationCallTx(txn types.Transaction, chain chainView) string {
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

	// The access list is the newer way to name what a call may touch. A call
	// uses it in place of the four lists above, so leaving it out would show
	// a call that reaches accounts and assets as reaching nothing.
	if len(txn.Access) > 0 {
		desc.WriteString(fmt.Sprintf("\n  Access: %d", len(txn.Access)))
		for i, ref := range txn.Access {
			desc.WriteString(fmt.Sprintf("\n    [%d]: %s", i, describeAccessRef(txn, ref)))
		}
	}

	if txn.RejectVersion != 0 {
		desc.WriteString(fmt.Sprintf(
			"\n  Reject Version: %d (the call fails if the app's version is %d or higher)",
			txn.RejectVersion, txn.RejectVersion))
	}

	return desc.String()
}

// describeAccessRef renders one access-list entry. Holding, locals and box
// entries point at earlier entries by a one-based index; zero means the
// sender for an account and the called app for an app.
func describeAccessRef(txn types.Transaction, ref types.ResourceRef) string {
	var parts []string
	if ref.Address != (types.Address{}) {
		parts = append(parts, "account "+ref.Address.String())
	}
	if ref.Asset != 0 {
		parts = append(parts, fmt.Sprintf("asset %d", ref.Asset))
	}
	if ref.App != 0 {
		parts = append(parts, fmt.Sprintf("app %d", ref.App))
	}
	if ref.Holding != (types.HoldingRef{}) {
		parts = append(parts, fmt.Sprintf("holding of %s by %s",
			accessAssetAt(txn, ref.Holding.Asset), accessAccountAt(txn, ref.Holding.Address)))
	}
	if ref.Locals != (types.LocalsRef{}) {
		parts = append(parts, fmt.Sprintf("local state of %s in %s",
			accessAccountAt(txn, ref.Locals.Address), accessAppAt(txn, ref.Locals.App)))
	}
	if ref.Box.ForeignAppIdx != 0 || len(ref.Box.Name) > 0 {
		parts = append(parts, fmt.Sprintf("box %s / %s",
			accessAppAt(txn, ref.Box.ForeignAppIdx), formatBoxName(ref.Box.Name)))
	}
	switch len(parts) {
	case 0:
		// Not a no-op: the network counts an empty entry as an empty box
		// reference, which raises the call's box read and write budget.
		return "(empty entry: adds box read/write budget)"
	case 1:
		return parts[0]
	default:
		// The protocol allows one kind per entry. Show all of what is there.
		return "MALFORMED, more than one kind: " + strings.Join(parts, "; ")
	}
}

func accessEntryAt(txn types.Transaction, index uint64) (types.ResourceRef, bool) {
	if index == 0 || index > uint64(len(txn.Access)) {
		return types.ResourceRef{}, false
	}
	return txn.Access[index-1], true
}

// unresolvedAccessRef names an entry a pointer leads to when that entry is
// missing or the wrong kind. The pointer is one-based on the wire; the rows
// above are labelled from zero, so it is shown as the row label.
func unresolvedAccessRef(txn types.Transaction, index uint64, wantKind string) string {
	if index > uint64(len(txn.Access)) {
		return fmt.Sprintf("?[%d] (no such entry)", index-1)
	}
	return fmt.Sprintf("?[%d] (not %s)", index-1, wantKind)
}

func accessAccountAt(txn types.Transaction, index uint64) string {
	if index == 0 {
		return "the sender"
	}
	if ref, ok := accessEntryAt(txn, index); ok && ref.Address != (types.Address{}) {
		return "account " + ref.Address.String()
	}
	return unresolvedAccessRef(txn, index, "an account")
}

func accessAssetAt(txn types.Transaction, index uint64) string {
	if ref, ok := accessEntryAt(txn, index); ok && ref.Asset != 0 {
		return fmt.Sprintf("asset %d", ref.Asset)
	}
	if index == 0 {
		return "?(no asset named)"
	}
	return unresolvedAccessRef(txn, index, "an asset")
}

func accessAppAt(txn types.Transaction, index uint64) string {
	if index == 0 {
		return "app " + calledAppLabel(txn)
	}
	if ref, ok := accessEntryAt(txn, index); ok && ref.App != 0 {
		return fmt.Sprintf("app %d", ref.App)
	}
	return unresolvedAccessRef(txn, index, "an app")
}

// calledAppLabel names the app a call addresses. A create has no ID yet.
func calledAppLabel(txn types.Transaction) string {
	if txn.ApplicationID == 0 {
		return "(the app being created)"
	}
	return fmt.Sprintf("%d (the called app)", txn.ApplicationID)
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
		if txn.ApplicationID == 0 {
			return "(the app being created)"
		}
		return fmt.Sprintf("%d", txn.ApplicationID)
	}
	idx := int(ref.ForeignAppIdx - 1)
	if idx >= 0 && idx < len(txn.ForeignApps) {
		return fmt.Sprintf("%d", txn.ForeignApps[idx])
	}
	return fmt.Sprintf("?idx=%d", ref.ForeignAppIdx)
}

func describeKeyRegistrationTx(txn types.Transaction, chain chainView) string {
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

func describeUnknownTx(txn types.Transaction, chain chainView) string {
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Transaction Type: %s", termsafe.Line(string(txn.Type))))
	desc.WriteString(fmt.Sprintf("\n  From: %s", txn.Sender.String()))
	return desc.String()
}

// appendCommonFields adds fee, network identity, note, close remainder, rekey, group, and round info.
func appendCommonFields(desc *strings.Builder, txn types.Transaction, chain chainView) {
	fmt.Fprintf(desc, "\n  Fee: %s ALGO", asaset.FormatFixed(uint64(txn.Fee), 6))

	if chain.network != "" {
		fmt.Fprintf(desc, "\n  Network: %s", termsafe.Line(chain.network))
	}
	if txn.GenesisID != "" {
		fmt.Fprintf(desc, "\n  GenesisID: %s", termsafe.Line(txn.GenesisID))
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
	network, _ := resolver.NetworkForGenesisHashBytes(txn.GenesisHash[:])
	return describe(txn, chainView{network: network})
}

// DescribeTxnInContext describes txn in a node's policy context: the network
// is the one the context maps the transaction's chain to, and an asset the
// context's ASA set knows is shown in its display units beside its base
// units. An approval prompt is built from the context its signing request
// captured, so a reload while it waits does not change what it says.
func DescribeTxnInContext(txn types.Transaction, ctx *policycontext.Context) string {
	if ctx == nil {
		return DescribeTxn(txn)
	}
	network, _ := ctx.Network(asaset.GenesisHash(txn.GenesisHash))
	return describe(txn, chainView{network: network, ctx: ctx})
}

func describe(txn types.Transaction, chain chainView) string {
	describer, exists := transactionDescribers[string(txn.Type)]
	if !exists {
		describer = describeUnknownTx
	}

	var builder strings.Builder
	builder.WriteString(describer(txn, chain))
	appendCommonFields(&builder, txn, chain)

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
