// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package txnreview turns a transaction into the lines a person reads before
// approving it. The signer's approval prompt and apshell's review of a
// plugin-built group both use it, so the two say the same thing about the same
// bytes. It reads only the transaction and, when given one, a table of known
// assets: nothing here belongs to the signer alone, and clients may import it.
package txnreview

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/termsafe"
)

type transactionDescriber func(txn types.Transaction, view View) Details

// Details is what a review says of one transaction, as data: a title that
// names what the transaction does, then one field per line of the review.
// Describe prints it, so the text and the fields cannot say different things.
type Details struct {
	Title  string
	Fields []Field
}

// Field is one line of a review.
type Field struct {
	// Label names the field. It is empty for a remark, a line that is only
	// its Value.
	Label string
	Value string
	// Party is the address Value names, when Value is one account's address.
	Party string
	// Alert marks a line the review warns of.
	Alert bool
	// Depth is 1 for an entry of the list the field above it opens.
	Depth int
	// wide pads the separator so a "To" lines up under a "From".
	wide bool
}

// Text prints the details as the review shows them: the title, then each
// field on its own indented line.
func (d Details) Text() string {
	var b strings.Builder
	b.WriteString(d.Title)
	for _, f := range d.Fields {
		b.WriteString("\n  ")
		if f.Depth > 0 {
			b.WriteString(strings.Repeat("  ", f.Depth))
		}
		if f.Alert {
			b.WriteString("⚠️  ")
		}
		switch {
		case f.Label == "":
		case f.wide:
			b.WriteString(f.Label + ":   ")
		default:
			b.WriteString(f.Label + ": ")
		}
		b.WriteString(f.Value)
	}
	return b.String()
}

func (d *Details) add(label, value string) {
	d.Fields = append(d.Fields, Field{Label: label, Value: value})
}

func (d *Details) addf(label, format string, args ...any) {
	d.add(label, fmt.Sprintf(format, args...))
}

// entry adds one entry of the list the field above it opens.
func (d *Details) entry(index int, value string) {
	d.Fields = append(d.Fields, Field{Label: fmt.Sprintf("[%d]", index), Value: value, Depth: 1})
}

func (d *Details) remark(text string) {
	d.Fields = append(d.Fields, Field{Value: text})
}

func (d *Details) account(label string, addr types.Address) {
	d.Fields = append(d.Fields, Field{Label: label, Value: addr.String(), Party: addr.String()})
}

// authority adds an asset role: an account, or the note that the role is off.
func (d *Details) authority(label string, addr types.Address) {
	if addr.IsZero() {
		d.add(label, formatAuthorityAddress(addr))
		return
	}
	d.account(label, addr)
}

// from and to add the two ends of a transfer, the "To" lined up under the
// "From".
func (d *Details) from(addr types.Address) { d.account("From", addr) }

func (d *Details) to(addr types.Address) {
	d.account("To", addr)
	d.Fields[len(d.Fields)-1].wide = true
}

func (d *Details) alert(label string, addr types.Address) {
	d.account(label, addr)
	d.Fields[len(d.Fields)-1].Alert = true
}

// View is what a description knows beyond the transaction itself: the token
// that names the transaction's network, and a table of assets that labels
// them. Both are optional. A client reviewing a plugin's group has neither,
// and gets IDs and base units.
type View struct {
	Network string
	Assets  *asaset.Table
}

// asset returns what the view's table knows of asset id on the transaction's
// chain.
func (v View) asset(genesis types.Digest, id uint64) (asaset.Asset, bool) {
	if v.Assets == nil {
		return asaset.Asset{}, false
	}
	return v.Assets.Lookup(asaset.Identity{Genesis: asaset.GenesisHash(genesis), AssetID: id})
}

// assetRef names asset id, with its unit name when the view's table knows it.
func (v View) assetRef(genesis types.Digest, id uint64) string {
	if a, ok := v.asset(genesis, id); ok {
		if unit := asaset.Printable(a.UnitName); unit != "" {
			return fmt.Sprintf("asset #%d (%s)", id, unit)
		}
	}
	return fmt.Sprintf("asset #%d", id)
}

func describePaymentTx(txn types.Transaction, view View) Details {
	d := Details{Title: fmt.Sprintf("Payment: %s ALGO", asaset.FormatFixed(uint64(txn.Amount), 6))}
	d.from(txn.Sender)
	d.to(txn.Receiver)

	if txn.Sender.String() == txn.Receiver.String() && txn.Amount == 0 {
		d.remark("[VALIDATION: 0 ALGO self-send]")
	}

	return d
}

func describeAssetTransferTx(txn types.Transaction, view View) Details {
	amount := fmt.Sprintf("%d base units", txn.AssetAmount)
	asset, known := view.asset(txn.GenesisHash, uint64(txn.XferAsset))
	if known {
		amount = asset.Display(txn.AssetAmount)
	}
	d := Details{Title: fmt.Sprintf("ASA Transfer: %s, asset #%d", amount, txn.XferAsset)}
	if view.Network != "" {
		d.Title += ", " + termsafe.Line(view.Network)
	}
	if !known && view.Assets != nil {
		d.remark("Not in this node's ASA set")
	}
	d.from(txn.Sender)
	d.to(txn.AssetReceiver)

	if isClawback(txn) {
		d.alert("CLAWBACK FROM", txn.AssetSender)
	} else if isSelfClawback(txn) {
		// Still a clawback on chain: the sender must hold the asset's
		// clawback role, and a freeze on its holding does not stop it. A
		// plain line, not the clawback warning: it is no finding.
		d.remark("Moves the sender's own holding by clawback authority, even if frozen")
	}

	if !txn.AssetCloseTo.IsZero() {
		d.account("Close remainder to", txn.AssetCloseTo)
	}

	return d
}

// isSelfClawback reports whether an asset transfer names its own sender as
// the account it takes from. That is a clawback too, of the sender's own
// holding. It is described, not a finding: the warnings, and the review they
// require, are for taking from someone else.
func isSelfClawback(txn types.Transaction) bool {
	return !txn.AssetSender.IsZero() && txn.AssetSender == txn.Sender
}

func describeAssetConfigTx(txn types.Transaction, view View) Details {
	var d Details
	roles := func() {
		d.authority("Manager", txn.AssetParams.Manager)
		d.authority("Reserve", txn.AssetParams.Reserve)
		d.authority("Freeze", txn.AssetParams.Freeze)
		d.authority("Clawback", txn.AssetParams.Clawback)
	}
	if txn.ConfigAsset == 0 {
		d.Title = "Asset Creation"
		d.from(txn.Sender)
		if txn.AssetParams.AssetName != "" {
			d.add("Name", termsafe.Line(txn.AssetParams.AssetName))
		}
		if txn.AssetParams.UnitName != "" {
			d.add("Unit", termsafe.Line(txn.AssetParams.UnitName))
		}
		d.addf("Total", "%d", txn.AssetParams.Total)
		d.addf("Decimals", "%d", txn.AssetParams.Decimals)
		d.addf("Default Frozen", "%t", txn.AssetParams.DefaultFrozen)
		roles()
		if txn.AssetParams.URL != "" {
			d.add("URL", termsafe.Line(txn.AssetParams.URL))
		}
		if !isZeroMetadataHash(txn.AssetParams.MetadataHash) {
			d.add("Metadata Hash", hex.EncodeToString(txn.AssetParams.MetadataHash[:]))
		}
	} else if txn.AssetParams.IsZero() {
		d.Title = "Asset Destroy: " + view.assetRef(txn.GenesisHash, uint64(txn.ConfigAsset))
		d.from(txn.Sender)
	} else {
		d.Title = "Asset Reconfiguration: " + view.assetRef(txn.GenesisHash, uint64(txn.ConfigAsset))
		d.from(txn.Sender)
		roles()
	}
	return d
}

func describeAssetFreezeTx(txn types.Transaction, view View) Details {
	d := Details{Title: "Asset Freeze: " + view.assetRef(txn.GenesisHash, uint64(txn.FreezeAsset))}
	d.from(txn.Sender)
	d.account("Account", txn.FreezeAccount)
	if txn.AssetFrozen {
		d.add("Action", "FREEZE")
	} else {
		d.add("Action", "UNFREEZE")
	}
	return d
}

func describeApplicationCallTx(txn types.Transaction, view View) Details {
	var d Details
	if txn.ApplicationID == 0 {
		d.Title = fmt.Sprintf("App Create (%s)", OnCompletionLabel(txn.OnCompletion))
	} else {
		d.Title = fmt.Sprintf("App Call: #%d (%s)", txn.ApplicationID, OnCompletionLabel(txn.OnCompletion))
	}
	d.from(txn.Sender)
	appendAppProgramDetails(&d, txn)

	if len(txn.ApplicationArgs) > 0 {
		d.addf("Args", "%d argument(s)", len(txn.ApplicationArgs))
		for i, arg := range txn.ApplicationArgs {
			d.entry(i, formatAppArg(i, arg))
		}
	}

	if len(txn.Accounts) > 0 {
		d.addf("Accounts", "%d", len(txn.Accounts))
		for i, addr := range txn.Accounts {
			d.entry(i, addr.String())
			d.Fields[len(d.Fields)-1].Party = addr.String()
		}
	}

	if len(txn.ForeignApps) > 0 {
		d.addf("Foreign Apps", "%d", len(txn.ForeignApps))
		for i, appID := range txn.ForeignApps {
			d.entry(i, fmt.Sprintf("%d", appID))
		}
	}

	if len(txn.ForeignAssets) > 0 {
		d.addf("Foreign Assets", "%d", len(txn.ForeignAssets))
		for i, assetID := range txn.ForeignAssets {
			d.entry(i, fmt.Sprintf("%d", assetID))
		}
	}

	if len(txn.BoxReferences) > 0 {
		d.addf("Boxes", "%d", len(txn.BoxReferences))
		for i, ref := range txn.BoxReferences {
			d.entry(i, fmt.Sprintf("app %s / %s", resolveBoxAppRef(txn, ref), formatBoxName(ref.Name)))
		}
	}

	// The access list is the newer way to name what a call may touch. A call
	// uses it in place of the four lists above, so leaving it out would show
	// a call that reaches accounts and assets as reaching nothing.
	if len(txn.Access) > 0 {
		d.addf("Access", "%d", len(txn.Access))
		for i, ref := range txn.Access {
			d.entry(i, describeAccessRef(txn, ref))
		}
	}

	if txn.RejectVersion != 0 {
		d.addf("Reject Version", "%d (the call fails if the app's version is %d or higher)",
			txn.RejectVersion, txn.RejectVersion)
	}

	return d
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

// OnCompletionLabel names an application call's on-completion action.
func OnCompletionLabel(onComp types.OnCompletion) string {
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

func describeKeyRegistrationTx(txn types.Transaction, view View) Details {
	var d Details

	if IsOfflineKeyReg(txn) {
		if txn.Nonparticipation {
			d.Title = "Key Registration: Go NONPARTICIPATING"
		} else {
			d.Title = "Key Registration: Go OFFLINE"
		}
	} else {
		d.Title = "Key Registration: Go ONLINE"
		// Whole keys, in base64: that is the form an operator has them in
		// (`goal account partkeyinfo`, `keyreg votekey=`), so they can be
		// compared. A prefix would let someone else's keys pass for one's own.
		d.add("VotePK", participationKey(txn.VotePK[:]))
		d.add("SelectionPK", participationKey(txn.SelectionPK[:]))
		d.addf("VoteFirst", "%d", txn.VoteFirst)
		d.addf("VoteLast", "%d", txn.VoteLast)
		d.addf("VoteKeyDilution", "%d", txn.VoteKeyDilution)
		d.add("StateProofPK", participationKey(txn.StateProofPK[:]))
		if txn.Nonparticipation {
			d.add("Nonparticipation", "true")
		}
	}
	d.from(txn.Sender)

	return d
}

func describeUnknownTx(txn types.Transaction, view View) Details {
	d := Details{Title: fmt.Sprintf("Transaction Type: %s", termsafe.Line(string(txn.Type)))}
	d.from(txn.Sender)
	// Say so: a short description must not read as a complete one.
	d.remark("[This type is not known here: the fields specific to it are NOT shown]")
	return d
}

// appendCommonFields adds fee, network identity, note, close remainder, rekey, group, and round info.
func appendCommonFields(d *Details, txn types.Transaction, view View) {
	d.addf("Fee", "%s ALGO", asaset.FormatFixed(uint64(txn.Fee), 6))

	if view.Network != "" {
		d.add("Network", termsafe.Line(view.Network))
	}
	if txn.GenesisID != "" {
		d.add("GenesisID", termsafe.Line(txn.GenesisID))
	}
	// The genesis ID is free text the builder of the transaction chose. When
	// no network name is known for the chain, the genesis hash is the only
	// thing that says which chain this is.
	if view.Network == "" && txn.GenesisHash != (types.Digest{}) {
		d.addf("Genesis hash", "%s (no network name known for it)", base64.StdEncoding.EncodeToString(txn.GenesisHash[:]))
	}

	if len(txn.Note) > 0 {
		d.add("Note", formatOpaqueBytes(txn.Note))
	}

	if !txn.CloseRemainderTo.IsZero() {
		d.account("Close remainder to", txn.CloseRemainderTo)
	}

	if !txn.RekeyTo.IsZero() {
		d.alert("REKEY TO", txn.RekeyTo)
	}

	// A lease blocks any other transaction from this sender with the same
	// lease until this one's last valid round.
	if txn.Lease != ([32]byte{}) {
		d.add("Lease", base64.StdEncoding.EncodeToString(txn.Lease[:]))
	}

	emptyGroup := types.Digest{}
	if txn.Group != emptyGroup {
		d.add("Group", hex.EncodeToString(txn.Group[:]))
		d.remark("[Part of atomic transaction group]")
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

// Describe returns the description of txn: what it does by type, then the
// fields every transaction has (fee, network, note, close, rekey, group). The
// text is built from the transaction passed in, so describe the transaction
// that will be signed, after any fee or group changes.
func Describe(txn types.Transaction, view View) string {
	return Detail(txn, view).Text()
}

// Detail returns what Describe prints, as data.
func Detail(txn types.Transaction, view View) Details {
	describer, exists := transactionDescribers[string(txn.Type)]
	if !exists {
		describer = describeUnknownTx
	}
	d := describer(txn, view)
	appendCommonFields(&d, txn, view)
	return d
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

func appendAppProgramDetails(d *Details, txn types.Transaction) {
	if len(txn.ApprovalProgram) > 0 {
		approvalHash := sha256.Sum256(txn.ApprovalProgram)
		d.addf("Approval Program", "%d bytes, sha256=%s",
			len(txn.ApprovalProgram), hex.EncodeToString(approvalHash[:]))
	}
	if len(txn.ClearStateProgram) > 0 {
		clearHash := sha256.Sum256(txn.ClearStateProgram)
		d.addf("Clear Program", "%d bytes, sha256=%s",
			len(txn.ClearStateProgram), hex.EncodeToString(clearHash[:]))
	}

	if txn.GlobalStateSchema.NumUint > 0 || txn.GlobalStateSchema.NumByteSlice > 0 {
		d.addf("Global Schema", "%d uint, %d bytes",
			txn.GlobalStateSchema.NumUint, txn.GlobalStateSchema.NumByteSlice)
	}
	if txn.LocalStateSchema.NumUint > 0 || txn.LocalStateSchema.NumByteSlice > 0 {
		d.addf("Local Schema", "%d uint, %d bytes",
			txn.LocalStateSchema.NumUint, txn.LocalStateSchema.NumByteSlice)
	}
	if txn.ExtraProgramPages > 0 {
		d.addf("Extra Program Pages", "%d", txn.ExtraProgramPages)
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

// participationKey shows a key in base64, or says there is none: an all-zero
// key printed in full would read as a real one.
func participationKey(key []byte) string {
	for _, b := range key {
		if b != 0 {
			return base64.StdEncoding.EncodeToString(key)
		}
	}
	return "(none)"
}
