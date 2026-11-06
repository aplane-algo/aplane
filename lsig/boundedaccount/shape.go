// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundedaccount implements aplane.bounded.v1, the general bounded key
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
	ParameterCosigner       = boundary.ParameterCosigner

	EncodingAuto   = boundary.EncodingAuto
	EncodingInline = boundary.EncodingInline
	EncodingMerkle = boundary.EncodingMerkle

	RekeySpendingKey = boundary.RekeySpendingKey
	RekeyAdminKey    = boundary.RekeyAdminKey

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
	Spend    []txeffects.SpendEffect
	Encoding string
	Rekey    string
	Cosigner bool
}

// Policy names the shape's framework Layer 3 policy.
func (s Shape) Policy() string {
	if s.Encoding == EncodingMerkle {
		return composeddsa.Layer3PolicyMerkleAllowlist
	}
	return composeddsa.Layer3PolicyFixedAllowlist
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
	return fmt.Sprintf("spend=%s;policy=%s;rekey=%s/%s;cosigner=%s",
		strings.Join(spend, ","), s.Policy(), s.Rekey, boundedmeta.PolicyGateNone, cosigner)
}

// Shapes enumerates every shape the grammar can select, in a stable order.
// A cosigner requires admin-key rekey, because rekey is mandatory in this grammar
// and bounded1 forbids spending-key rekey with a cosigner.
func Shapes() []Shape {
	type family struct {
		rekey    string
		cosigner bool
	}
	families := []family{{RekeySpendingKey, false}, {RekeyAdminKey, false}, {RekeyAdminKey, true}}
	var shapes []Shape
	for _, encoding := range []string{EncodingInline, EncodingMerkle} {
		for _, f := range families {
			for mask := 1; mask < 1<<len(spendEffectOrder); mask++ {
				var spend []txeffects.SpendEffect
				for bit, effect := range spendEffectOrder {
					if mask&(1<<bit) != 0 {
						spend = append(spend, effect)
					}
				}
				shapes = append(shapes, Shape{Spend: spend, Encoding: encoding, Rekey: f.rekey, Cosigner: f.cosigner})
			}
		}
	}
	return shapes
}
