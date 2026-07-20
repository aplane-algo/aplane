// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package txeffects defines neutral transaction-effect facts used by the
// bounded contract and off-chain policy consumers.
package txeffects

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// EffectKind identifies an authority-bearing transaction effect.
type EffectKind string

const (
	EffectRekey      EffectKind = "rekey"
	EffectClose      EffectKind = "close"
	EffectAssetClose EffectKind = "asset_close"
	EffectClawback   EffectKind = "clawback"
)

// SpendEffect identifies one bounded1 spend normal form.
type SpendEffect string

const (
	SpendEffectPay        SpendEffect = "pay"
	SpendEffectAxfer      SpendEffect = "axfer"
	SpendEffectAssetOptIn SpendEffect = "asset_opt_in"
)

// TxField identifies an SDK transaction field inspected by the contract.
type TxField string

const (
	FieldRekeyTo          TxField = "RekeyTo"
	FieldCloseRemainderTo TxField = "CloseRemainderTo"
	FieldAssetCloseTo     TxField = "AssetCloseTo"
	FieldAssetSender      TxField = "AssetSender"
)

// NonZeroTest identifies the predicate applied to a transaction field.
type NonZeroTest string

const (
	TestAddressNonZero NonZeroTest = "address_nonzero"
)

// FieldPredicate maps a semantic effect to its transaction-field predicate.
type FieldPredicate struct {
	Effect EffectKind
	Field  TxField
	Test   NonZeroTest
}

// ContractManifest is the semantic input shared by bounded renderers and
// off-chain classifiers. Its slices must be treated as ordered sets.
type ContractManifest struct {
	Contract         string
	TEALVersion      int
	SpendEffects     []SpendEffect
	Predicates       []FieldPredicate
	KnownDeniedTypes []types.TxType
}

var bounded1Manifest = mustValidManifest(ContractManifest{
	Contract:     "bounded1",
	TEALVersion:  12,
	SpendEffects: []SpendEffect{SpendEffectPay, SpendEffectAxfer, SpendEffectAssetOptIn},
	Predicates: []FieldPredicate{
		{Effect: EffectRekey, Field: FieldRekeyTo, Test: TestAddressNonZero},
		{Effect: EffectClose, Field: FieldCloseRemainderTo, Test: TestAddressNonZero},
		{Effect: EffectAssetClose, Field: FieldAssetCloseTo, Test: TestAddressNonZero},
		{Effect: EffectClawback, Field: FieldAssetSender, Test: TestAddressNonZero},
	},
	KnownDeniedTypes: []types.TxType{
		"",
		types.KeyRegistrationTx,
		types.AssetConfigTx,
		types.AssetFreezeTx,
		types.ApplicationCallTx,
		types.StateProofTx,
		types.HeartbeatTx,
	},
})

func mustValidManifest(manifest ContractManifest) ContractManifest {
	if err := manifest.Validate(); err != nil {
		panic(fmt.Sprintf("invalid built-in bounded1 manifest: %v", err))
	}
	return manifest
}

// Bounded1Manifest returns a defensive copy of the frozen bounded1 manifest.
func Bounded1Manifest() ContractManifest {
	return cloneManifest(bounded1Manifest)
}

func cloneManifest(manifest ContractManifest) ContractManifest {
	manifest.SpendEffects = append([]SpendEffect(nil), manifest.SpendEffects...)
	manifest.Predicates = append([]FieldPredicate(nil), manifest.Predicates...)
	manifest.KnownDeniedTypes = append([]types.TxType(nil), manifest.KnownDeniedTypes...)
	return manifest
}

// Validate checks the structural invariants required of a contract manifest.
func (manifest ContractManifest) Validate() error {
	if manifest.Contract == "" {
		return fmt.Errorf("contract is required")
	}
	if manifest.TEALVersion <= 0 {
		return fmt.Errorf("TEAL version must be positive")
	}
	if len(manifest.SpendEffects) == 0 {
		return fmt.Errorf("at least one spend effect is required")
	}
	if len(manifest.Predicates) == 0 {
		return fmt.Errorf("at least one danger predicate is required")
	}

	seenSpendEffects := make(map[SpendEffect]struct{}, len(manifest.SpendEffects))
	allowedTypes := make(map[types.TxType]struct{}, len(manifest.SpendEffects))
	for _, effect := range manifest.SpendEffects {
		txType, ok := transactionTypeForSpendEffect(effect)
		if !ok {
			return fmt.Errorf("unknown spend effect %q", effect)
		}
		if _, exists := seenSpendEffects[effect]; exists {
			return fmt.Errorf("spend effect %q is duplicated", effect)
		}
		seenSpendEffects[effect] = struct{}{}
		allowedTypes[txType] = struct{}{}
	}
	seenTypes := make(map[types.TxType]struct{}, len(manifest.KnownDeniedTypes))
	for _, txType := range manifest.KnownDeniedTypes {
		if _, ok := allowedTypes[txType]; ok {
			return fmt.Errorf("transaction type %q is represented by spend effects and known denied types", txType)
		}
		if _, exists := seenTypes[txType]; exists {
			return fmt.Errorf("transaction type %q is duplicated in known denied types", txType)
		}
		seenTypes[txType] = struct{}{}
	}

	seenEffects := make(map[EffectKind]struct{}, len(manifest.Predicates))
	seenFields := make(map[TxField]struct{}, len(manifest.Predicates))
	for _, predicate := range manifest.Predicates {
		if predicate.Effect == "" || predicate.Field == "" {
			return fmt.Errorf("effect and field are required")
		}
		if _, ok := bitForEffect(predicate.Effect); !ok {
			return fmt.Errorf("unknown effect %q", predicate.Effect)
		}
		if !knownField(predicate.Field) {
			return fmt.Errorf("unknown transaction field %q", predicate.Field)
		}
		if predicate.Test != TestAddressNonZero {
			return fmt.Errorf("field %s uses unsupported predicate %q", predicate.Field, predicate.Test)
		}
		if _, ok := seenEffects[predicate.Effect]; ok {
			return fmt.Errorf("effect %q is duplicated", predicate.Effect)
		}
		if _, ok := seenFields[predicate.Field]; ok {
			return fmt.Errorf("field %q is duplicated", predicate.Field)
		}
		seenEffects[predicate.Effect] = struct{}{}
		seenFields[predicate.Field] = struct{}{}
	}
	return nil
}

func transactionTypeForSpendEffect(effect SpendEffect) (types.TxType, bool) {
	switch effect {
	case SpendEffectPay:
		return types.PaymentTx, true
	case SpendEffectAxfer, SpendEffectAssetOptIn:
		return types.AssetTransferTx, true
	default:
		return "", false
	}
}

func knownField(field TxField) bool {
	switch field {
	case FieldRekeyTo, FieldCloseRemainderTo, FieldAssetCloseTo, FieldAssetSender:
		return true
	default:
		return false
	}
}
