// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundedaccount implements aplane.falcon1024-b.v1, the general bounded key
// type. An account chooses its rules at generation from a closed set of built-in
// shapes, each an ordinary bounded composition with no author TEAL.
package boundedaccount

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
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

	EncodingAuto   = boundary.EncodingAuto
	EncodingInline = boundary.EncodingInline
	EncodingMerkle = boundary.EncodingMerkle

	RekeySpendingKey = boundary.RekeySpendingKey
	RekeyRefused     = boundary.RekeyRefused

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
}

// Policy names the shape's framework Layer 3 policy.
func (s Shape) Policy() string {
	switch {
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

// Shapes enumerates every shape the grammar can select, in a stable order. Allowlist
// shapes come first, so this order extends rather than reshuffles.
//
// A cosigned shape refuses rekeys: a cosigned rekey arrives with the cosigner
// overlay. A timelock refuses rekeys too, because no host rule gates a rekey, so a
// spending-key rekey could leave the lock at any time. A shape that refuses rekeys
// must leave a way out for what it holds (refusedSpendError).
func Shapes() []Shape {
	type family struct {
		rekey    string
		cosigner bool
	}
	families := []family{{RekeySpendingKey, false}, {RekeyRefused, false}, {RekeyRefused, true}}
	var shapes []Shape
	forEachShape := func(encoding string, timelock bool) {
		for _, f := range families {
			for mask := 1; mask < 1<<len(spendEffectOrder); mask++ {
				var spend []txeffects.SpendEffect
				for bit, effect := range spendEffectOrder {
					if mask&(1<<bit) != 0 {
						spend = append(spend, effect)
					}
				}
				if f.rekey == RekeyRefused && refusedSpendError(spend) != nil {
					continue
				}
				if timelock && f.rekey == RekeySpendingKey {
					continue
				}
				shapes = append(shapes, Shape{Spend: spend, Encoding: encoding, Rekey: f.rekey, Cosigner: f.cosigner, Timelock: timelock})
			}
		}
	}
	for _, encoding := range []string{EncodingInline, EncodingMerkle} {
		forEachShape(encoding, false)
	}
	for _, encoding := range []string{"", EncodingInline, EncodingMerkle} {
		forEachShape(encoding, true)
	}
	return shapes
}

// refusedSpendError reports why a shape that refuses rekeys could trap what it
// holds. With no rekey path and no close, a transfer is the only way out: pay for
// its ALGO, and axfer for any asset it can opt into. An account that never closes
// keeps its minimum balance regardless.
func refusedSpendError(spend []txeffects.SpendEffect) error {
	switch {
	case !slices.Contains(spend, txeffects.SpendEffectPay):
		return fmt.Errorf("%s=%s requires pay in %s", ParameterRekeyAuthority, RekeyRefused, ParameterSpendEffects)
	case slices.Contains(spend, txeffects.SpendEffectAssetOptIn) && !slices.Contains(spend, txeffects.SpendEffectAxfer):
		return fmt.Errorf("%s=%s with asset_opt_in requires axfer in %s", ParameterRekeyAuthority, RekeyRefused, ParameterSpendEffects)
	}
	return nil
}
