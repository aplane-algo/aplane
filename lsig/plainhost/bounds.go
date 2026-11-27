// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// The bounds: a request with any of the boundary grammar's bounds parameters
// selects a bounded2 shape over the plain host's base, the host rules beside
// the overlays.
const (
	// AutoInlineMax is the largest list auto encodes inline. It is part of the
	// grammar's meaning, so changing it changes the grammar fingerprint.
	AutoInlineMax = 10
	// InlineMax is the largest list inline encoding accepts.
	InlineMax = composeddsa.BoundedInlineListMax
	// RecipientsMax is the largest list any encoding accepts.
	RecipientsMax = merkleallowlist.MaxItems

	// shapeDerivationVersion is the template schema's derivation version for a
	// shape's spec. The host's own salt style replaces it when the shape is
	// composed.
	shapeDerivationVersion = 3
	merkleProofArg         = "merkle_proof"
	merkleProofSize        = 512
)

// boundsParameters are the parameters that select a shape.
var boundsParameters = []string{
	boundary.ParameterSpendEffects, boundary.ParameterRecipients, boundary.ParameterRecipientScope, boundary.ParameterListEncoding, boundary.ParameterMaxFee,
}

// hasBounds reports whether a request asks for a bounded2 shape.
func hasBounds(params map[string]string) bool {
	for _, name := range boundsParameters {
		if _, ok := params[name]; ok {
			return true
		}
	}
	return false
}

// spendEffectOrder is the canonical order of a spend subset.
var spendEffectOrder = []txeffects.SpendEffect{
	txeffects.SpendEffectPay,
	txeffects.SpendEffectAxfer,
	txeffects.SpendEffectAssetOptIn,
}

// Shape is one bounded2 account the grammar can select: the bounds, and the
// overlay arrangement beside them.
type Shape struct {
	Arrangement
	// Spend is a non-empty subset in canonical order.
	Spend []txeffects.SpendEffect
	// Encoding is empty when the shape has no recipient list.
	Encoding string
	// AnyRecipient is the limits-only shape: no recipient list, so the
	// envelope's fee ceiling and transfer kinds are the whole rule. It is
	// an explicit field, not an empty Encoding, so no zero value selects it.
	AnyRecipient bool
}

// arrangementSetting is the contract's rekey setting under a rekey option: only
// these is refused plus the list, plus cosigned a spending-key rekey plus the list.
func arrangementSetting(rekey string) hostmeta.RekeySetting {
	if rekey == boundary.RekeySpendingKey || rekey == boundary.RekeyPlusCosigned {
		return hostmeta.RekeySpendingKey
	}
	return hostmeta.RekeyRefused
}

// Policy names the shape's framework Layer 3 policy.
func (s Shape) Policy() string {
	switch {
	case s.AnyRecipient:
		return hostmeta.Layer3PolicyNone
	case s.Encoding == boundary.EncodingMerkle:
		return hostmeta.Layer3PolicyMerkleAllowlist
	default:
		return hostmeta.Layer3PolicyFixedAllowlist
	}
}

// Descriptor labels the shape in its fingerprints, so it names everything that
// tells two shapes apart. Its format is frozen by the fingerprint goldens.
func (s Shape) Descriptor() string {
	spend := make([]string, len(s.Spend))
	for i, effect := range s.Spend {
		spend[i] = string(effect)
	}
	// The default type's label predates other types and is frozen with it.
	cosigner := "none"
	switch s.Cosigner {
	case "":
	case hostmeta.DefaultCosignerComponentKeyType:
		cosigner = "required"
	default:
		cosigner = s.Cosigner
	}
	return fmt.Sprintf("spend=%s;policy=%s;rekey=%s;cosigner=%s",
		strings.Join(spend, ","), s.Policy(), s.Rekey, cosigner)
}

// Shapes enumerates every shape, in a stable order: inline and Merkle
// allowlists, then limits-only. Within each, every overlay arrangement in
// Arrangements order, and within that every transfer subset. The grammar is
// every combination the contracts allow (ninth amendment): a refused rekey and
// a refused account that can't send what it holds are shapes too. Which one
// suits an account is the user's choice; the review says what it means.
func Shapes() []Shape {
	var shapes []Shape
	family := func(encoding string, anyRecipient bool) {
		for _, arrangement := range Arrangements() {
			for mask := 1; mask < 1<<len(spendEffectOrder); mask++ {
				var spend []txeffects.SpendEffect
				for bit, effect := range spendEffectOrder {
					if mask&(1<<bit) != 0 {
						spend = append(spend, effect)
					}
				}
				shapes = append(shapes, Shape{
					Arrangement: arrangement, Spend: spend, Encoding: encoding, AnyRecipient: anyRecipient,
				})
			}
		}
	}
	for _, encoding := range []string{boundary.EncodingInline, boundary.EncodingMerkle} {
		family(encoding, false)
	}
	family("", true)
	return shapes
}

// shapeSpec expresses a shape in the expert template schema under the host's own
// identity, so a shape gets every check an imported template gets and cannot
// reach a composer state a template could not.
func shapeSpec(plain Plain, shape Shape, maxFee uint64) (*composeddsa.TemplateSpec, error) {
	publisher, family, version, err := splitKeyType(plain.KeyType())
	if err != nil {
		return nil, err
	}
	derivationVersion := shapeDerivationVersion
	opcodeCost := uint64(opcodeCost)
	spend := make([]string, len(shape.Spend))
	for i, effect := range shape.Spend {
		spend[i] = string(effect)
	}
	bounded := &generictemplate.BoundedAuthorizationSpec{
		Contract:     hostmeta.BoundedContract,
		SpendEffects: spend,
		MaxFee:       &maxFee,
		Layer3:       &generictemplate.TransactionLayer3Spec{Policy: shape.Policy()},
		Rekey:        shape.Rekey,
	}
	if shape.Cosigner != "" {
		// The cosigner signs every spend, and every rekey the spending key
		// declares; a listed rekey never asks it.
		bounded.Cosigner = &generictemplate.BoundedCosignerSpec{
			Contract:         hostmeta.CosignerContractV1,
			RequiredOn:       hostmeta.CosignerRequiredOn(arrangementSetting(shape.Rekey)),
			ComponentKeyType: shape.Cosigner,
		}
	}
	var parameters []generictemplate.ParameterSpec
	if shape.Encoding != "" {
		bounded.Layer3.RecipientsParameter = boundary.ParameterRecipients
		maxItems := InlineMax
		if shape.Encoding == boundary.EncodingMerkle {
			maxItems = RecipientsMax
		}
		parameters = append(parameters, generictemplate.ParameterSpec{
			Name:        boundary.ParameterRecipients,
			Label:       "Allowed Recipients",
			Description: "Addresses that may receive payments or asset transfers.",
			Type:        "address[]",
			Required:    true,
			MinItems:    1,
			MaxItems:    maxItems,
		})
	}
	if shape.Encoding == boundary.EncodingMerkle {
		bounded.DerivedArgs = []generictemplate.BoundedDerivedArgSpec{{
			Name:      merkleProofArg,
			Kind:      hostmeta.DerivedArgMerkleProof,
			Parameter: boundary.ParameterRecipients,
			MaxSize:   merkleProofSize,
		}}
	}
	return &composeddsa.TemplateSpec{
		SchemaVersion:     composeddsa.CurrentTemplateSchemaVersion,
		DerivationVersion: &derivationVersion,
		TemplateType:      "composed",
		BaseKeyType:       plain.KeyType(),
		TemplateMode:      generictemplate.TemplateModeStrict,
		Publisher:         publisher,
		Family:            family,
		Version:           version,
		DisplayName:       plain.DisplayName(),
		Description:       plain.Description(),
		MaxOpcodeCost:     &opcodeCost,
		Bounded:           bounded,
		Parameters:        parameters,
	}, nil
}

// newShapeComposer composes a shape over the host's base, under its identity and
// salt style.
func newShapeComposer(plain Plain, base Base, shape Shape, maxFee uint64) (*composeddsa.ComposedDSA, error) {
	spec, err := shapeSpec(plain, shape, maxFee)
	if err != nil {
		return nil, err
	}
	composer, err := composeddsa.NewHostProviderFromTemplateSpec(spec, composeddsa.BaseRegistration{
		BaseKeyType: plain.KeyType(),
		FamilyName:  plain.RoutingFamily(),
		Version:     plain.Version(),
		Ops:         base.Ops,
	}, base.SaltStyle)
	if err != nil {
		return nil, err
	}
	metadata := composer.HostMetadata()
	if metadata == nil || metadata.Contract != hostmeta.BoundedContract || storedCosigner(metadata) != shape.Cosigner {
		return nil, fmt.Errorf("the bounded program has no valid contract")
	}
	return composer, nil
}

// splitKeyType splits publisher.family.vN into its parts.
func splitKeyType(keyType string) (publisher, family string, version int, err error) {
	first := strings.Index(keyType, ".")
	last := strings.LastIndex(keyType, ".v")
	if first <= 0 || last <= first {
		return "", "", 0, fmt.Errorf("key type %q is not publisher.family.vN", keyType)
	}
	version, err = strconv.Atoi(keyType[last+2:])
	if err != nil || version <= 0 {
		return "", "", 0, fmt.Errorf("key type %q has no version", keyType)
	}
	return keyType[:first], keyType[first+1 : last], version, nil
}
