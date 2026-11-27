// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// selection is the shape and canonical values one bounds request resolves to.
type selection struct {
	shape Shape
	// maxFee is the fee ceiling the shape is compiled with.
	maxFee uint64
	values map[string]string
}

// selectShape is the security gate for a bounds request, whose values are all
// non-empty (present refuses an empty one). A boundary file is only one way to reach it, so every rule a file
// must obey is checked here on the flat parameters. Its output selects the same
// shape when resolved again, because the generator resolves the persisted values
// a second time.
func selectShape(params map[string]string, defs []lsigprovider.ParameterDef) (*selection, error) {
	if err := checkKnown(params, defs); err != nil {
		return nil, err
	}
	normalized, err := lsigprovider.NormalizeCreationParams(params, defs)
	if err != nil {
		return nil, err
	}

	spend, err := canonicalSpend(normalized[boundary.ParameterSpendEffects])
	if err != nil {
		return nil, err
	}
	overlays, err := resolveOverlays(params, normalized)
	if err != nil {
		return nil, err
	}
	scope, err := canonicalRecipientScope(params)
	if err != nil {
		return nil, err
	}
	maxFee, err := canonicalMaxFee(params)
	if err != nil {
		return nil, err
	}
	anyRecipient := scope == boundary.RecipientScopeAny
	var recipients []string
	encoding := ""
	if anyRecipient {
		// Limits-only: the request asked for no list, so it may not carry one.
		if _, present := params[boundary.ParameterRecipients]; present {
			return nil, fmt.Errorf("%s=%s takes no %s", boundary.ParameterRecipientScope, boundary.RecipientScopeAny, boundary.ParameterRecipients)
		}
		if _, present := params[boundary.ParameterListEncoding]; present {
			return nil, fmt.Errorf("%s has no list to encode", boundary.ParameterListEncoding)
		}
	} else {
		if recipients, err = canonicalRecipients(normalized[boundary.ParameterRecipients]); err != nil {
			return nil, err
		}
		if encoding, err = selectEncoding(params, len(recipients)); err != nil {
			return nil, err
		}
	}

	values := map[string]string{boundary.ParameterSpendEffects: joinSpend(spend)}
	overlays.addTo(values)
	if recipients != nil {
		values[boundary.ParameterListEncoding] = encoding
		values[boundary.ParameterRecipients] = strings.Join(recipients, ",")
	}
	// Only "any" is persisted: "listed" is the default.
	if anyRecipient {
		values[boundary.ParameterRecipientScope] = boundary.RecipientScopeAny
	}
	// Likewise only a ceiling other than the default.
	if maxFee != boundary.DefaultMaxFee {
		values[boundary.ParameterMaxFee] = strconv.FormatUint(maxFee, 10)
	}
	return &selection{
		maxFee: maxFee,
		shape: Shape{
			Arrangement: overlays.arrangement, Spend: spend, Encoding: encoding, AnyRecipient: anyRecipient,
		},
		values: values,
	}, nil
}

// overlays is a request's overlay choices, resolved the same way for a bounds
// request and an overlays-only one. The arrangement's Cosigner is the
// cosigner's key type, and cosigner its public key.
type overlays struct {
	arrangement Arrangement
	cosigner    string
	rekeyTo     string
}

// resolveOverlays checks the rekey setting, the cosigner and the rekey-to list.
// Plus cosigned needs a cosigner: without one the spending key would rekey
// anywhere, so the list would add nothing, and that is spending_key.
func resolveOverlays(params, normalized map[string]string) (overlays, error) {
	cosigner := normalized[hostmeta.CosignerPublicKeyParameter]
	cosignerType, err := resolveCosignerType(cosigner, normalized[hostmeta.CosignerKeyTypeParameter])
	if err != nil {
		return overlays{}, err
	}
	rekey := normalized[boundary.ParameterRekeyAuthority]
	if !slices.Contains(RekeyAuthorities, rekey) {
		return overlays{}, fmt.Errorf("%s must be %s", boundary.ParameterRekeyAuthority, strings.Join(RekeyAuthorities, ", "))
	}
	if rekey == boundary.RekeyPlusCosigned && cosigner == "" {
		return overlays{}, fmt.Errorf("%s=%s needs a cosigner; without one it is %s=%s",
			boundary.ParameterRekeyAuthority, boundary.RekeyPlusCosigned, boundary.ParameterRekeyAuthority, boundary.RekeySpendingKey)
	}
	rekeyTo, err := canonicalRekeyTo(params, normalized, rekey)
	if err != nil {
		return overlays{}, err
	}
	return overlays{arrangement: Arrangement{Rekey: rekey, Cosigner: cosignerType}, cosigner: cosigner, rekeyTo: rekeyTo}, nil
}

// resolveCosignerType is the key type of a request's cosigner, empty for none.
// The type defaults when the request names none, and must be one a plain host
// takes; it means nothing without a cosigner, and the key must be its size.
func resolveCosignerType(cosigner, cosignerType string) (string, error) {
	if cosigner == "" {
		if cosignerType != "" {
			return "", fmt.Errorf("%s needs a cosigner", hostmeta.CosignerKeyTypeParameter)
		}
		return "", nil
	}
	if cosignerType == "" {
		cosignerType = hostmeta.DefaultCosignerComponentKeyType
	}
	if !slices.Contains(CosignerKeyTypes, cosignerType) {
		return "", fmt.Errorf("%s must be %s", hostmeta.CosignerKeyTypeParameter, strings.Join(CosignerKeyTypes, " or "))
	}
	publicKeySize, _, _ := hostmeta.CosignerSizes(cosignerType)
	// NormalizeCreationParams has made the key canonical hex, with no prefix.
	publicKey, err := hex.DecodeString(cosigner)
	if err != nil {
		return "", fmt.Errorf("invalid %s hex: %w", hostmeta.CosignerPublicKeyParameter, err)
	}
	if len(publicKey) != publicKeySize {
		err := fmt.Errorf("%s is %d bytes; a %s key is %d", hostmeta.CosignerPublicKeyParameter, len(publicKey), cosignerType, publicKeySize)
		for _, other := range CosignerKeyTypes {
			if size, _, _ := hostmeta.CosignerSizes(other); size == len(publicKey) && other != cosignerType {
				err = fmt.Errorf("%w: for a %s key, set %s=%s", err, other, hostmeta.CosignerKeyTypeParameter, other)
			}
		}
		return "", err
	}
	return cosignerType, nil
}

// addTo writes the overlays' canonical values.
func (o overlays) addTo(values map[string]string) {
	values[boundary.ParameterRekeyAuthority] = o.arrangement.Rekey
	if o.cosigner != "" {
		values[hostmeta.CosignerPublicKeyParameter] = o.cosigner
	}
	// Recorded only when it is not the default, so a default-cosigned
	// account keeps the parameters it has always had.
	if o.arrangement.Cosigner != "" && o.arrangement.Cosigner != hostmeta.DefaultCosignerComponentKeyType {
		values[hostmeta.CosignerKeyTypeParameter] = o.arrangement.Cosigner
	}
	if o.rekeyTo != "" {
		values[boundary.ParameterRekeyTo] = o.rekeyTo
	}
}

// checkKnown refuses a parameter the type doesn't declare, and a cosigner
// reference the signer hasn't resolved to its key.
func checkKnown(params map[string]string, defs []lsigprovider.ParameterDef) error {
	known := make(map[string]bool, len(defs))
	for _, def := range defs {
		known[def.Name] = true
	}
	for name := range params {
		if name == boundary.ParameterCosigner {
			return fmt.Errorf("cosigner reference was not resolved")
		}
		if !known[name] {
			return fmt.Errorf("unknown parameter %q", name)
		}
	}
	return nil
}

// canonicalRekeyTo returns the rekey-to list in canonical order, or "" for an
// account without one. only_these and plus_cosigned take a list, and must have one.
func canonicalRekeyTo(params, normalized map[string]string, rekey string) (string, error) {
	_, present := params[boundary.ParameterRekeyTo]
	if !(Arrangement{Rekey: rekey}).HasRekeyList() {
		if present {
			return "", fmt.Errorf("%s needs %s=%s or %s", boundary.ParameterRekeyTo, boundary.ParameterRekeyAuthority, boundary.RekeyOnlyThese, boundary.RekeyPlusCosigned)
		}
		return "", nil
	}
	if strings.TrimSpace(normalized[boundary.ParameterRekeyTo]) == "" {
		return "", fmt.Errorf("%s=%s needs the addresses the account may be rekeyed to in %s", boundary.ParameterRekeyAuthority, rekey, boundary.ParameterRekeyTo)
	}
	entries, err := composeddsa.RekeyListEntries(normalized)
	if err != nil {
		return "", err
	}
	addresses := make([]string, len(entries))
	for i, entry := range entries {
		addresses[i] = entry.String()
	}
	return strings.Join(addresses, ","), nil
}

// canonicalRecipientScope returns "" when the request names no scope.
func canonicalRecipientScope(params map[string]string) (string, error) {
	scope, present := params[boundary.ParameterRecipientScope]
	if !present {
		return "", nil
	}
	switch scope {
	case boundary.RecipientScopeAny, boundary.RecipientScopeListed:
		return scope, nil
	default:
		return "", fmt.Errorf("%s must be %s or %s", boundary.ParameterRecipientScope, boundary.RecipientScopeListed, boundary.RecipientScopeAny)
	}
}

// canonicalMaxFee returns the fee ceiling, the default when the request names
// none.
func canonicalMaxFee(params map[string]string) (uint64, error) {
	value, present := params[boundary.ParameterMaxFee]
	if !present {
		return boundary.DefaultMaxFee, nil
	}
	return boundary.ParseMaxFee(value)
}

func canonicalSpend(value string) ([]txeffects.SpendEffect, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%s is required with bounds", boundary.ParameterSpendEffects)
	}
	seen := make(map[txeffects.SpendEffect]bool)
	for _, item := range strings.Split(value, ",") {
		effect := txeffects.SpendEffect(strings.TrimSpace(item))
		if !slices.Contains(spendEffectOrder, effect) {
			return nil, fmt.Errorf("%s has unknown effect %q", boundary.ParameterSpendEffects, item)
		}
		if seen[effect] {
			return nil, fmt.Errorf("%s repeats %q", boundary.ParameterSpendEffects, effect)
		}
		seen[effect] = true
	}
	var canonical []txeffects.SpendEffect
	for _, effect := range spendEffectOrder {
		if seen[effect] {
			canonical = append(canonical, effect)
		}
	}
	return canonical, nil
}

func joinSpend(spend []txeffects.SpendEffect) string {
	items := make([]string, len(spend))
	for i, effect := range spend {
		items[i] = string(effect)
	}
	return strings.Join(items, ",")
}

// canonicalRecipients expects a list NormalizeCreationParams has already sorted.
func canonicalRecipients(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%s is required", boundary.ParameterRecipients)
	}
	recipients := strings.Split(value, ",")
	if len(recipients) > RecipientsMax {
		return nil, fmt.Errorf("%s has %d addresses, maximum is %d", boundary.ParameterRecipients, len(recipients), RecipientsMax)
	}
	for i, recipient := range recipients {
		address, err := types.DecodeAddress(recipient)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid address %q: %w", boundary.ParameterRecipients, recipient, err)
		}
		if address == (types.Address{}) {
			return nil, fmt.Errorf("%s must not contain the zero address", boundary.ParameterRecipients)
		}
		if i > 0 && recipient == recipients[i-1] {
			return nil, fmt.Errorf("%s repeats %s", boundary.ParameterRecipients, recipient)
		}
	}
	return recipients, nil
}

// selectEncoding reads the request, where an absent encoding means auto.
func selectEncoding(params map[string]string, count int) (string, error) {
	encoding, present := params[boundary.ParameterListEncoding]
	if !present {
		encoding = boundary.EncodingAuto
	}
	switch encoding {
	case boundary.EncodingAuto:
		if count <= AutoInlineMax {
			return boundary.EncodingInline, nil
		}
		return boundary.EncodingMerkle, nil
	case boundary.EncodingInline:
		if count > InlineMax {
			return "", fmt.Errorf("inline encoding accepts at most %d recipients, got %d", InlineMax, count)
		}
		return boundary.EncodingInline, nil
	case boundary.EncodingMerkle:
		return boundary.EncodingMerkle, nil
	default:
		return "", fmt.Errorf("%s must be %s, %s or %s", boundary.ParameterListEncoding, boundary.EncodingAuto, boundary.EncodingInline, boundary.EncodingMerkle)
	}
}
