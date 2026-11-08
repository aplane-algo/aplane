// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundedaccount implements aplane.falcon1024-b.v1, the general bounded key
// type. An account chooses its rules at generation from a closed set of built-in
// shapes, each an ordinary bounded composition with no author TEAL.
package boundedaccount

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

const (
	KeyTypeV1        = boundary.KeyTypeV1
	BoundarySchemaV1 = boundary.SchemaV1

	ParameterSpendEffects   = boundary.ParameterSpendEffects
	ParameterRekeyAuthority = boundary.ParameterRekeyAuthority
	ParameterListEncoding   = boundary.ParameterListEncoding
	ParameterRecipients     = boundary.ParameterRecipients
	ParameterUnlockRound    = boundary.ParameterUnlockRound
	ParameterCosigner       = boundary.ParameterCosigner
	ParameterRecipientScope = boundary.ParameterRecipientScope

	RecipientScopeListed = boundary.RecipientScopeListed
	RecipientScopeAny    = boundary.RecipientScopeAny

	EncodingAuto   = boundary.EncodingAuto
	EncodingInline = boundary.EncodingInline
	EncodingMerkle = boundary.EncodingMerkle

	RekeySpendingKey  = boundary.RekeySpendingKey
	RekeyOnlyThese    = boundary.RekeyOnlyThese
	RekeyPlusCosigned = boundary.RekeyPlusCosigned
	RekeyRefused      = boundary.RekeyRefused

	ParameterRekeyTo = boundary.ParameterRekeyTo

	// AutoInlineMax is the largest list auto encodes inline. It is part of the
	// grammar's meaning, so changing it changes the grammar fingerprint.
	AutoInlineMax = 10
	// InlineMax is the largest list inline encoding accepts.
	InlineMax = composeddsa.BoundedInlineListMax
	// RecipientsMax is the largest list any encoding accepts.
	RecipientsMax = merkleallowlist.MaxItems

	// MaxFee is the compiled fee ceiling of every shape, in microAlgos.
	MaxFee uint64 = 10_000
)

// spendEffectOrder is the canonical order of a spend subset.
var spendEffectOrder = []txeffects.SpendEffect{
	txeffects.SpendEffectPay,
	txeffects.SpendEffectAxfer,
	txeffects.SpendEffectAssetOptIn,
}

// Shape is one account definition the grammar can select.
type Shape struct {
	// Spend is a non-empty subset in canonical order.
	Spend []txeffects.SpendEffect
	// Encoding is empty when the shape has no recipient list.
	Encoding string
	Rekey    string
	Cosigner bool
	// Timelock requires an unlock round before anything can be spent.
	Timelock bool
	// AnyRecipient is the limits-only shape: no recipient list and no timelock,
	// so the envelope's fee ceiling and transfer kinds are the whole rule. It is
	// an explicit field, not an empty Encoding, so no zero value selects it.
	AnyRecipient bool
}

// HasRekeyList reports whether the shape takes a rekey-to list.
func (s Shape) HasRekeyList() bool {
	return s.Rekey == RekeyOnlyThese || s.Rekey == RekeyPlusCosigned
}

// rekeySetting is the contract's rekey setting under the shape's option: only
// these is refused plus the list, plus cosigned a spending-key rekey plus the list.
func (s Shape) rekeySetting() boundedmeta.RekeySetting {
	switch s.Rekey {
	case RekeyOnlyThese:
		return boundedmeta.RekeyRefused
	case RekeyPlusCosigned:
		return boundedmeta.RekeySpendingKey
	default:
		return boundedmeta.RekeySetting(s.Rekey)
	}
}

// Policy names the shape's framework Layer 3 policy.
func (s Shape) Policy() string {
	switch {
	case s.AnyRecipient:
		return composeddsa.Layer3PolicyNone
	case s.Timelock && s.Encoding == EncodingMerkle:
		return composeddsa.Layer3PolicyMerkleAllowlistTimelock
	case s.Timelock && s.Encoding == EncodingInline:
		return composeddsa.Layer3PolicyFixedAllowlistTimelock
	case s.Timelock:
		return composeddsa.Layer3PolicyTimelock
	case s.Encoding == EncodingMerkle:
		return composeddsa.Layer3PolicyMerkleAllowlist
	default:
		return composeddsa.Layer3PolicyFixedAllowlist
	}
}

// Descriptor labels the shape in its fingerprints, so it names everything that
// tells two shapes apart. Its format is frozen by the fingerprint goldens.
func (s Shape) Descriptor() string {
	spend := make([]string, len(s.Spend))
	for i, effect := range s.Spend {
		spend[i] = string(effect)
	}
	cosigner := "none"
	if s.Cosigner {
		cosigner = "required"
	}
	return fmt.Sprintf("spend=%s;policy=%s;rekey=%s;cosigner=%s",
		strings.Join(spend, ","), s.Policy(), s.Rekey, cosigner)
}

// Shapes enumerates every shape the grammar can select, in a stable order:
// allowlists, then timelocks, then limits-only shapes. Each family is appended
// after the last, so this order extends rather than reshuffles.
//
// Every shape has a way out: a spending-key rekey (with the cosigner on a
// cosigned shape), a rekey-to list, or both (plus cosigned). The grammar never
// offers an account that refuses every rekey. A timelock takes only a rekey-to
// list, because no host rule gates a rekey: a spending-key rekey, cosigned or not,
// could leave the lock at any time. A list is a way around the lock too, which
// the review names.
func Shapes() []Shape {
	type family struct {
		rekey    string
		cosigner bool
	}
	families := []family{
		{RekeySpendingKey, false}, {RekeyOnlyThese, false},
		{RekeySpendingKey, true}, {RekeyOnlyThese, true}, {RekeyPlusCosigned, true},
	}
	var shapes []Shape
	forEachShape := func(encoding string, timelock, anyRecipient bool) {
		for _, f := range families {
			for mask := 1; mask < 1<<len(spendEffectOrder); mask++ {
				var spend []txeffects.SpendEffect
				for bit, effect := range spendEffectOrder {
					if mask&(1<<bit) != 0 {
						spend = append(spend, effect)
					}
				}
				if timelock && f.rekey != RekeyOnlyThese {
					continue
				}
				shapes = append(shapes, Shape{
					Spend: spend, Encoding: encoding, Rekey: f.rekey, Cosigner: f.cosigner,
					Timelock: timelock, AnyRecipient: anyRecipient,
				})
			}
		}
	}
	for _, encoding := range []string{EncodingInline, EncodingMerkle} {
		forEachShape(encoding, false, false)
	}
	for _, encoding := range []string{"", EncodingInline, EncodingMerkle} {
		forEachShape(encoding, true, false)
	}
	forEachShape("", false, true)
	return shapes
}
