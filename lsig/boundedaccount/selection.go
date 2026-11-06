// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"fmt"
	"slices"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// selection is the shape and canonical values one request resolves to.
type selection struct {
	shape  Shape
	values map[string]string
}

// selectShape is the security gate for creation requests. A boundary file is
// only one way to reach it, so every rule a file must obey is checked here on
// the flat parameters. Its output selects the same shape when resolved again,
// because the generator resolves the persisted values a second time.
func selectShape(params map[string]string, defs []lsigprovider.ParameterDef) (*selection, error) {
	known := make(map[string]bool, len(defs))
	for _, def := range defs {
		known[def.Name] = true
	}
	for name := range params {
		if name == ParameterCosigner {
			return nil, fmt.Errorf("cosigner reference was not resolved")
		}
		if !known[name] {
			return nil, fmt.Errorf("unknown parameter %q", name)
		}
	}
	normalized, err := lsigprovider.NormalizeCreationParams(params, defs)
	if err != nil {
		return nil, err
	}

	spend, err := canonicalSpend(normalized[ParameterSpendEffects])
	if err != nil {
		return nil, err
	}
	rekey := normalized[ParameterRekeyAuthority]
	if rekey != RekeySpendingKey && rekey != RekeyAdminKey {
		return nil, fmt.Errorf("%s must be %s or %s", ParameterRekeyAuthority, RekeySpendingKey, RekeyAdminKey)
	}
	recipients, err := canonicalRecipients(normalized[ParameterRecipients])
	if err != nil {
		return nil, err
	}
	encoding, err := selectEncoding(params, len(recipients))
	if err != nil {
		return nil, err
	}

	admin := normalized[composeddsa.BoundedAdminPublicKeyParameter]
	cosigner := normalized[composeddsa.BoundedCosignerPublicKeyParameter]
	if _, present := params[composeddsa.BoundedCosignerPublicKeyParameter]; present && cosigner == "" {
		return nil, fmt.Errorf("%s is empty", composeddsa.BoundedCosignerPublicKeyParameter)
	}
	switch {
	case rekey == RekeyAdminKey && admin == "":
		return nil, fmt.Errorf("%s=%s requires %s", ParameterRekeyAuthority, RekeyAdminKey, composeddsa.BoundedAdminPublicKeyParameter)
	case rekey == RekeySpendingKey && admin != "":
		return nil, fmt.Errorf("%s=%s does not use %s", ParameterRekeyAuthority, RekeySpendingKey, composeddsa.BoundedAdminPublicKeyParameter)
	case rekey == RekeySpendingKey && cosigner != "":
		return nil, fmt.Errorf("a cosigner requires %s=%s", ParameterRekeyAuthority, RekeyAdminKey)
	case admin != "" && admin == cosigner:
		return nil, fmt.Errorf("bounded cosigner witness key must differ from the contract-admin key")
	}

	values := map[string]string{
		ParameterSpendEffects:   joinSpend(spend),
		ParameterRekeyAuthority: rekey,
		ParameterListEncoding:   encoding,
		ParameterRecipients:     strings.Join(recipients, ","),
	}
	if admin != "" {
		values[composeddsa.BoundedAdminPublicKeyParameter] = admin
	}
	if cosigner != "" {
		values[composeddsa.BoundedCosignerPublicKeyParameter] = cosigner
	}
	return &selection{
		shape:  Shape{Spend: spend, Encoding: encoding, Rekey: rekey, Cosigner: cosigner != ""},
		values: values,
	}, nil
}

func canonicalSpend(value string) ([]txeffects.SpendEffect, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%s is required", ParameterSpendEffects)
	}
	seen := make(map[txeffects.SpendEffect]bool)
	for _, item := range strings.Split(value, ",") {
		effect := txeffects.SpendEffect(strings.TrimSpace(item))
		if !slices.Contains(spendEffectOrder, effect) {
			return nil, fmt.Errorf("%s has unknown effect %q", ParameterSpendEffects, item)
		}
		if seen[effect] {
			return nil, fmt.Errorf("%s repeats %q", ParameterSpendEffects, effect)
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
		return nil, fmt.Errorf("%s is required", ParameterRecipients)
	}
	recipients := strings.Split(value, ",")
	if len(recipients) > RecipientsMax {
		return nil, fmt.Errorf("%s has %d addresses, maximum is %d", ParameterRecipients, len(recipients), RecipientsMax)
	}
	for i, recipient := range recipients {
		address, err := types.DecodeAddress(recipient)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid address %q: %w", ParameterRecipients, recipient, err)
		}
		if address == (types.Address{}) {
			return nil, fmt.Errorf("%s must not contain the zero address", ParameterRecipients)
		}
		if i > 0 && recipient == recipients[i-1] {
			return nil, fmt.Errorf("%s repeats %s", ParameterRecipients, recipient)
		}
	}
	return recipients, nil
}

// selectEncoding reads the original request, because an explicitly empty value
// is an error rather than a request for the default.
func selectEncoding(params map[string]string, count int) (string, error) {
	encoding, present := params[ParameterListEncoding]
	if !present {
		encoding = EncodingAuto
	}
	switch encoding {
	case EncodingAuto:
		if count <= AutoInlineMax {
			return EncodingInline, nil
		}
		return EncodingMerkle, nil
	case EncodingInline:
		if count > InlineMax {
			return "", fmt.Errorf("inline encoding accepts at most %d recipients, got %d", InlineMax, count)
		}
		return EncodingInline, nil
	case EncodingMerkle:
		return EncodingMerkle, nil
	default:
		return "", fmt.Errorf("%s must be %s, %s or %s", ParameterListEncoding, EncodingAuto, EncodingInline, EncodingMerkle)
	}
}
