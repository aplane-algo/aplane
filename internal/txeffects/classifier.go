// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

type effectSet uint8

const (
	effectRekeyBit effectSet = 1 << iota
	effectCloseBit
	effectAssetCloseBit
	effectClawbackBit
)

// Shape is the bounded1 classification of a finalized transaction before fee
// and profile-specific spending-policy evaluation.
type Shape string

const (
	ShapePureSpend    Shape = "pure_spend"
	ShapePureRekey    Shape = "pure_rekey"
	ShapeHybrid       Shape = "hybrid"
	ShapeDeniedEffect Shape = "denied_effect"
	ShapeDeniedType   Shape = "denied_type"
)

// Facts contains neutral observations about a finalized transaction.
type Facts struct {
	TransactionType types.TxType
	Fee             types.MicroAlgos
	effects         effectSet
}

// Has reports whether the transaction carries the given effect.
func (facts Facts) Has(effect EffectKind) bool {
	bit, ok := bitForEffect(effect)
	return ok && facts.effects&bit != 0
}

// Effects returns detected effects in frozen manifest order.
func (facts Facts) Effects() []EffectKind {
	effects := make([]EffectKind, 0, len(bounded1Manifest.Predicates))
	for _, predicate := range bounded1Manifest.Predicates {
		if facts.Has(predicate.Effect) {
			effects = append(effects, predicate.Effect)
		}
	}
	return effects
}

// Classification combines neutral facts with the bounded1 shape decision.
type Classification struct {
	Facts       Facts
	Shape       Shape
	SpendEffect SpendEffect
}

// Inspect returns neutral facts using the frozen bounded1 danger manifest.
func Inspect(txn types.Transaction) Facts {
	facts := Facts{TransactionType: txn.Type, Fee: txn.Fee}
	for _, predicate := range bounded1Manifest.Predicates {
		if mustMatch(txn, predicate) {
			facts.effects |= mustEffectBit(predicate.Effect)
		}
	}
	return facts
}

// Classify returns the bounded1 transaction shape. Fee bounds and configured
// Layer-3 spending policy are intentionally evaluated by later consumers.
func Classify(txn types.Transaction) Classification {
	facts := Inspect(txn)
	classification := Classification{Facts: facts}

	if facts.effects == 0 {
		switch txn.Type {
		case types.PaymentTx:
			classification.Shape = ShapePureSpend
			classification.SpendEffect = SpendEffectPay
		case types.AssetTransferTx:
			classification.Shape = ShapePureSpend
			classification.SpendEffect = SpendEffectAxfer
			if txn.AssetAmount == 0 && txn.AssetReceiver == txn.Sender {
				classification.SpendEffect = SpendEffectAssetOptIn
			}
		default:
			classification.Shape = ShapeDeniedType
		}
		return classification
	}

	if facts.Has(EffectRekey) {
		if facts.effects == effectRekeyBit &&
			txn.Type == types.PaymentTx &&
			txn.Amount == 0 &&
			txn.Receiver == txn.Sender {
			classification.Shape = ShapePureRekey
		} else {
			classification.Shape = ShapeHybrid
		}
		return classification
	}

	classification.Shape = ShapeDeniedEffect
	return classification
}

func mustMatch(txn types.Transaction, predicate FieldPredicate) bool {
	if predicate.Test != TestAddressNonZero {
		panic(fmt.Sprintf("unsupported bounded1 predicate test %q", predicate.Test))
	}
	switch predicate.Field {
	case FieldRekeyTo:
		return !txn.RekeyTo.IsZero()
	case FieldCloseRemainderTo:
		return !txn.CloseRemainderTo.IsZero()
	case FieldAssetCloseTo:
		return !txn.AssetCloseTo.IsZero()
	case FieldAssetSender:
		return !txn.AssetSender.IsZero()
	default:
		panic(fmt.Sprintf("unsupported bounded1 predicate field %q", predicate.Field))
	}
}

func bitForEffect(effect EffectKind) (effectSet, bool) {
	switch effect {
	case EffectRekey:
		return effectRekeyBit, true
	case EffectClose:
		return effectCloseBit, true
	case EffectAssetClose:
		return effectAssetCloseBit, true
	case EffectClawback:
		return effectClawbackBit, true
	default:
		return 0, false
	}
}

func mustEffectBit(effect EffectKind) effectSet {
	bit, ok := bitForEffect(effect)
	if !ok {
		panic(fmt.Sprintf("unsupported bounded1 effect %q", effect))
	}
	return bit
}
