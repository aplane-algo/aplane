// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

// DefaultMaxFeeMicroAlgos is the fee above which a transaction's fee is a
// finding: 1 ALGO.
const DefaultMaxFeeMicroAlgos = 1_000_000

// Finding is one thing a reviewer must not miss in a transaction: a field
// that hands over control or funds beyond the stated amount, or uses an
// authority over someone else's holding.
type Finding struct {
	Field    string
	Value    string
	Critical bool
	Message  string
}

// FindingContext is what a check knows about the reviewer's own position.
// All of it is optional: with none, a rekey reads as a loss of control.
type FindingContext struct {
	// KnownAddresses is the set of addresses the signer holds. A rekey to one
	// of them is still a finding, but it says the signer keeps control instead
	// of warning that control is lost.
	KnownAddresses map[string]bool
	// ProtocolRekeyTargets are rekey targets the signer itself set as part of
	// a signing protocol and proved before approval ran: a rotating account's
	// next stage. A rekey to one of them is the protocol working, not a
	// dangerous field, and produces no finding.
	ProtocolRekeyTargets map[string]bool
	// ListedRekeyTargets are addresses on a signing account's rekey-to list. A
	// rekey to one is still a finding: it hands the account over.
	ListedRekeyTargets map[string]bool
}

// Findings lists what a reviewer must not miss in txn. The signer's approval
// warnings and apshell's review of a plugin-built group are both built from
// it, so a field that warns in one warns in the other.
func Findings(txn types.Transaction, ctx FindingContext) []Finding {
	var violations []Finding
	facts := txeffects.Inspect(txn)

	if facts.Has(txeffects.EffectRekey) && !ctx.ProtocolRekeyTargets[txn.RekeyTo.String()] {
		rekeyTarget := txn.RekeyTo.String()
		msg := "This transaction will transfer signing authority to another address."
		if ctx.ListedRekeyTargets[rekeyTarget] {
			msg = "This transaction hands the account to an address on its rekey-to list."
		}
		switch {
		case ctx.KnownAddresses[rekeyTarget]:
			msg += "\n   You possess the keys for the new address."
		case ctx.ListedRekeyTargets[rekeyTarget]:
			msg += "\n   >>> THIS SIGNER DOES NOT HOLD IT: THE ACCOUNT LEAVES THIS SIGNER'S CUSTODY <<<"
		default:
			msg += "\n   >>> YOU WILL LOSE CONTROL OF THIS ACCOUNT <<<"
		}
		violations = append(violations, Finding{
			Field:    "RekeyTo",
			Value:    rekeyTarget,
			Critical: true,
			Message:  msg,
		})
	}

	if facts.Has(txeffects.EffectClose) {
		violations = append(violations, Finding{
			Field:    "CloseRemainderTo",
			Value:    txn.CloseRemainderTo.String(),
			Critical: true,
			Message:  "This transaction will close your account and send ALL remaining ALGO to another address.",
		})
	}

	if facts.Has(txeffects.EffectAssetClose) {
		violations = append(violations, Finding{
			Field:   "AssetCloseTo",
			Value:   txn.AssetCloseTo.String(),
			Message: "This transaction will send your ENTIRE balance of this asset to another address.",
		})
	}

	if facts.Has(txeffects.EffectClawback) && isClawback(txn) {
		violations = append(violations, Finding{
			Field:   "AssetSender",
			Value:   txn.AssetSender.String(),
			Message: "CLAWBACK: This transaction will move funds from another account using your clawback authority.",
		})
	}

	if txn.Type == types.ApplicationCallTx {
		switch txn.OnCompletion {
		case types.DeleteApplicationOC:
			violations = append(violations, Finding{
				Field:   "OnCompletion",
				Value:   "DeleteApplication",
				Message: "This transaction will DELETE the application.",
			})
		case types.ClearStateOC:
			violations = append(violations, Finding{
				Field:   "OnCompletion",
				Value:   "ClearState",
				Message: "This transaction will force-clear your local state for the application.",
			})
		case types.UpdateApplicationOC:
			violations = append(violations, Finding{
				Field:   "OnCompletion",
				Value:   "UpdateApplication",
				Message: "This transaction will REPLACE the application's approval and clear-state programs.",
			})
		}
	}

	// Asset creation (ConfigAsset 0) is routine; reconfiguring or destroying
	// an existing asset changes who controls it, permanently where a role is
	// cleared.
	if txn.Type == types.AssetConfigTx && txn.ConfigAsset != 0 {
		if txn.AssetParams == (types.AssetParams{}) {
			violations = append(violations, Finding{
				Field:    "ConfigAsset",
				Value:    fmt.Sprintf("%d", txn.ConfigAsset),
				Critical: true,
				Message:  fmt.Sprintf("This transaction will DESTROY asset #%d. The asset ID is retired permanently.", txn.ConfigAsset),
			})
		} else {
			violations = append(violations, Finding{
				Field: "ConfigAsset",
				Value: fmt.Sprintf("%d", txn.ConfigAsset),
				Message: fmt.Sprintf("This transaction will RECONFIGURE the authority addresses of asset #%d. A cleared role cannot be restored."+
					"\n   Manager: %s\n   Reserve: %s\n   Freeze: %s\n   Clawback: %s",
					txn.ConfigAsset, assetRoleAddress(txn.AssetParams.Manager), assetRoleAddress(txn.AssetParams.Reserve),
					assetRoleAddress(txn.AssetParams.Freeze), assetRoleAddress(txn.AssetParams.Clawback)),
			})
		}
	}

	if txn.Type == types.AssetFreezeTx {
		action := "UNFREEZE"
		if txn.AssetFrozen {
			action = "FREEZE"
		}
		violations = append(violations, Finding{
			Field:   "FreezeAccount",
			Value:   txn.FreezeAccount.String(),
			Message: fmt.Sprintf("This transaction will %s the account's holding of asset #%d using your freeze authority.", action, txn.FreezeAsset),
		})
	}

	if uint64(txn.Fee) > DefaultMaxFeeMicroAlgos {
		algoFee := asaset.FormatFixed(uint64(txn.Fee), 6)
		violations = append(violations, Finding{
			Field:   "Fee",
			Value:   algoFee + " ALGO",
			Message: fmt.Sprintf("Transaction fee is unusually high (%s ALGO). Normal fees are ~0.001 ALGO.", algoFee),
		})
	}

	return violations
}

// assetRoleAddress names an asset role address, or its permanent clearing.
func assetRoleAddress(addr types.Address) string {
	if addr.IsZero() {
		return "(cleared)"
	}
	return addr.String()
}

// isClawback reports whether an asset transfer takes from someone other than
// its sender.
func isClawback(txn types.Transaction) bool {
	return !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender
}

// IsOfflineKeyReg reports whether a key registration carries no participation
// keys at all, which is what takes an account offline.
func IsOfflineKeyReg(txn types.Transaction) bool {
	return txn.VotePK == (types.VotePK{}) && txn.SelectionPK == (types.VRFPK{})
}
