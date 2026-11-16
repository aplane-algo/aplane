// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
)

// EffectKind names what a transaction does between the parties it touches.
type EffectKind string

const (
	EffectTransfer     EffectKind = "transfer"
	EffectSelfSend     EffectKind = "self_send"
	EffectOptIn        EffectKind = "opt_in"
	EffectClose        EffectKind = "close"
	EffectClawback     EffectKind = "clawback"
	EffectFreeze       EffectKind = "freeze"
	EffectRekey        EffectKind = "rekey"
	EffectAppCall      EffectKind = "app_call"
	EffectKeyReg       EffectKind = "keyreg"
	EffectAssetCreate  EffectKind = "asset_create"
	EffectAssetConfig  EffectKind = "asset_config"
	EffectAssetDestroy EffectKind = "asset_destroy"
)

// Severity is how much attention an effect asks for. It is taken from the
// findings on the same transaction, so a picture of the effects and the list
// of findings never disagree.
type Severity string

const (
	SeverityNormal  Severity = ""
	SeverityCaution Severity = "caution"
	SeverityDanger  Severity = "danger"
)

// Effect is one thing a transaction does, for a picture of the request: who
// it moves value or control from and to, in a few words. It summarizes the
// fields; it never says more than they do.
type Effect struct {
	Kind EffectKind
	// From and To are account addresses. To is empty for an effect on From
	// alone, and for an app call, which names its app instead.
	From, To string
	// Authority is the account that acts when it is neither end: the sender
	// of a clawback.
	Authority string
	// App is the called application. NewApp is set when the call creates it.
	App    uint64
	NewApp bool
	// Text is the amount or the action, in a few words.
	Text     string
	Severity Severity
	// field is the finding field that speaks of this effect.
	field string
}

// effects lists what txn does. Severity is not set here: Mark sets it from
// the findings.
func effects(txn types.Transaction, view View) []Effect {
	sender := txn.Sender.String()
	var out []Effect
	arrow := func(kind EffectKind, to types.Address, text, field string) {
		out = append(out, Effect{Kind: kind, From: sender, To: to.String(), Text: text, field: field})
	}
	mark := func(kind EffectKind, text, field string) {
		out = append(out, Effect{Kind: kind, From: sender, Text: text, field: field})
	}
	rekeys := !txn.RekeyTo.IsZero()

	switch txn.Type {
	case types.PaymentTx:
		amount := asaset.FormatFixed(uint64(txn.Amount), 6) + " ALGO"
		closes := !txn.CloseRemainderTo.IsZero()
		switch {
		case txn.Amount == 0 && (closes || (rekeys && txn.Receiver == txn.Sender)):
			// The payment only carries the close or the rekey.
		case txn.Receiver == txn.Sender:
			mark(EffectSelfSend, amount+" to itself", "")
		default:
			arrow(EffectTransfer, txn.Receiver, amount, "Receiver")
		}
		if closes {
			arrow(EffectClose, txn.CloseRemainderTo, "CLOSE: all remaining ALGO", "CloseRemainderTo")
		}
	case types.AssetTransferTx:
		name := view.assetName(txn.GenesisHash, uint64(txn.XferAsset))
		amount := view.assetAmount(txn.GenesisHash, uint64(txn.XferAsset), txn.AssetAmount)
		closes := !txn.AssetCloseTo.IsZero()
		switch {
		case isClawback(txn):
			out = append(out, Effect{Kind: EffectClawback, From: txn.AssetSender.String(), To: txn.AssetReceiver.String(),
				Authority: sender, Text: "CLAWBACK " + amount, field: "AssetSender"})
		case txn.AssetAmount == 0 && closes:
			// The transfer only carries the close.
		case txn.AssetReceiver == txn.Sender && txn.AssetAmount == 0:
			mark(EffectOptIn, "opt in to "+name, "")
		case txn.AssetReceiver == txn.Sender:
			mark(EffectSelfSend, amount+" to itself", "")
		default:
			arrow(EffectTransfer, txn.AssetReceiver, amount, "")
		}
		if closes {
			arrow(EffectClose, txn.AssetCloseTo, "CLOSE: all remaining "+name, "AssetCloseTo")
		}
	case types.AssetFreezeTx:
		verb := "unfreeze "
		if txn.AssetFrozen {
			verb = "freeze "
		}
		arrow(EffectFreeze, txn.FreezeAccount, verb+view.assetName(txn.GenesisHash, uint64(txn.FreezeAsset)), "FreezeAccount")
	case types.ApplicationCallTx:
		out = append(out, Effect{Kind: EffectAppCall, From: sender, App: uint64(txn.ApplicationID), NewApp: txn.ApplicationID == 0,
			Text: appCallText(txn), field: "OnCompletion"})
	case types.KeyRegistrationTx:
		switch {
		case txn.Nonparticipation:
			mark(EffectKeyReg, "NONPARTICIPATING, for good", "Nonparticipation")
		case IsOfflineKeyReg(txn):
			mark(EffectKeyReg, "go offline", "")
		default:
			mark(EffectKeyReg, "go online", "KeyRegistration")
		}
	case types.AssetConfigTx:
		switch {
		case txn.ConfigAsset == 0:
			text := "create asset"
			if unit := asaset.Printable(txn.AssetParams.UnitName); unit != "" {
				text += " " + unit
			}
			mark(EffectAssetCreate, text, "")
		case txn.AssetParams.IsZero():
			mark(EffectAssetDestroy, "DESTROY "+view.assetName(txn.GenesisHash, uint64(txn.ConfigAsset)), "ConfigAsset")
		default:
			mark(EffectAssetConfig, "reconfigure "+view.assetName(txn.GenesisHash, uint64(txn.ConfigAsset)), "ConfigAsset")
		}
	}

	if rekeys {
		if txn.RekeyTo == txn.Sender {
			out = append(out, Effect{Kind: EffectRekey, From: sender, To: sender, Text: "rekey to its own address", field: "RekeyTo"})
		} else {
			arrow(EffectRekey, txn.RekeyTo, "REKEY: control moves", "RekeyTo")
		}
	}
	return out
}

func appCallText(txn types.Transaction) string {
	if txn.ApplicationID == 0 {
		return "create app"
	}
	switch txn.OnCompletion {
	case types.NoOpOC:
		return "call"
	case types.OptInOC:
		return "opt in"
	case types.CloseOutOC:
		return "close out"
	case types.ClearStateOC:
		return "clear state"
	case types.UpdateApplicationOC:
		return "UPDATE program"
	case types.DeleteApplicationOC:
		return "DELETE app"
	}
	return OnCompletionLabel(txn.OnCompletion)
}

// assetName names asset id in a word: its unit name when the view's table
// knows one, its ID otherwise.
func (v View) assetName(genesis types.Digest, id uint64) string {
	if a, ok := v.asset(genesis, id); ok {
		if unit := asaset.Printable(a.UnitName); unit != "" {
			return unit
		}
	}
	return fmt.Sprintf("asset #%d", id)
}

// assetAmount is an amount of asset id in a few words: in display units when
// the view's table knows the asset, in base units otherwise.
func (v View) assetAmount(genesis types.Digest, id, raw uint64) string {
	if a, ok := v.asset(genesis, id); ok {
		if unit := asaset.Printable(a.UnitName); unit != "" {
			return asaset.FormatUnits(raw, a.Decimals) + " " + unit
		}
	}
	return fmt.Sprintf("%d base units of asset #%d", raw, id)
}

// Mark sets each effect's severity from findings, the findings of the same
// transaction: danger where a critical finding speaks of the effect, caution
// where any other does, and normal where none does.
func (d *Details) Mark(findings []Finding) {
	for i := range d.Effects {
		effect := &d.Effects[i]
		effect.Severity = SeverityNormal
		if effect.field == "" {
			continue
		}
		for _, finding := range findings {
			if finding.Field != effect.field {
				continue
			}
			if finding.Critical {
				effect.Severity = SeverityDanger
				break
			}
			effect.Severity = SeverityCaution
		}
	}
}
