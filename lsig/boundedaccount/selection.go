// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"fmt"
	"slices"
	"strconv"
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
	switch rekey {
	case RekeySpendingKey, RekeyOnlyThese, RekeyPlusCosigned:
	case RekeyRefused:
		// An account that refuses every rekey has no way out but its transfers.
		return nil, fmt.Errorf("%s=%s is not offered: use %s=%s with the addresses the account may be rekeyed to in %s",
			ParameterRekeyAuthority, RekeyRefused, ParameterRekeyAuthority, RekeyOnlyThese, ParameterRekeyTo)
	default:
		return nil, fmt.Errorf("%s must be %s, %s or %s", ParameterRekeyAuthority, RekeySpendingKey, RekeyOnlyThese, RekeyPlusCosigned)
	}
	rekeyTo, err := canonicalRekeyTo(params, normalized, rekey)
	if err != nil {
		return nil, err
	}
	unlockRound, err := canonicalUnlockRound(params)
	if err != nil {
		return nil, err
	}
	timelock := unlockRound != ""
	scope, err := canonicalRecipientScope(params)
	if err != nil {
		return nil, err
	}
	anyRecipient := scope == RecipientScopeAny
	var recipients []string
	encoding := ""
	if anyRecipient {
		// Limits-only: the request asked for no list, so it may not carry one,
		// and a timelock already admits any recipient once it unlocks.
		if _, present := params[ParameterRecipients]; present {
			return nil, fmt.Errorf("%s=%s takes no %s", ParameterRecipientScope, RecipientScopeAny, ParameterRecipients)
		}
		if _, present := params[ParameterListEncoding]; present {
			return nil, fmt.Errorf("%s has no list to encode", ParameterListEncoding)
		}
		if timelock {
			return nil, fmt.Errorf("%s=%s does not combine with %s; a timelock alone admits any recipient once it unlocks",
				ParameterRecipientScope, RecipientScopeAny, ParameterUnlockRound)
		}
	} else if _, present := params[ParameterRecipients]; present || !timelock || scope == RecipientScopeListed {
		if recipients, err = canonicalRecipients(normalized[ParameterRecipients]); err != nil {
			return nil, err
		}
		if encoding, err = selectEncoding(params, len(recipients)); err != nil {
			return nil, err
		}
	} else if _, present := params[ParameterListEncoding]; present {
		return nil, fmt.Errorf("%s has no list to encode", ParameterListEncoding)
	}

	cosigner := normalized[composeddsa.BoundedCosignerPublicKeyParameter]
	if _, present := params[composeddsa.BoundedCosignerPublicKeyParameter]; present && cosigner == "" {
		return nil, fmt.Errorf("%s is empty", composeddsa.BoundedCosignerPublicKeyParameter)
	}
	switch {
	case rekey == RekeyPlusCosigned && cosigner == "":
		// Without a cosigner the spending key would rekey anywhere, so the list
		// would add nothing.
		return nil, fmt.Errorf("%s=%s needs a cosigner; without one, use %s=%s or %s",
			ParameterRekeyAuthority, RekeyPlusCosigned, ParameterRekeyAuthority, RekeyOnlyThese, RekeySpendingKey)
	case timelock && rekey != RekeyOnlyThese:
		// No host rule gates a rekey, so a spending-key rekey, cosigned or not,
		// would leave the lock early.
		return nil, fmt.Errorf("a timelock can't take %s=%s: a spending-key rekey would leave the lock before the unlock round; use %s=%s",
			ParameterRekeyAuthority, rekey, ParameterRekeyAuthority, RekeyOnlyThese)
	}

	values := map[string]string{
		ParameterSpendEffects:   joinSpend(spend),
		ParameterRekeyAuthority: rekey,
	}
	if recipients != nil {
		values[ParameterListEncoding] = encoding
		values[ParameterRecipients] = strings.Join(recipients, ",")
	}
	if timelock {
		values[ParameterUnlockRound] = unlockRound
	}
	// Only "any" is persisted: "listed" is the default, so the values of every
	// earlier shape stay as they were.
	if anyRecipient {
		values[ParameterRecipientScope] = RecipientScopeAny
	}
	if rekeyTo != "" {
		values[ParameterRekeyTo] = rekeyTo
	}
	if cosigner != "" {
		values[composeddsa.BoundedCosignerPublicKeyParameter] = cosigner
	}
	return &selection{
		shape: Shape{
			Spend: spend, Encoding: encoding, Rekey: rekey, Cosigner: cosigner != "",
			Timelock: timelock, AnyRecipient: anyRecipient,
		},
		values: values,
	}, nil
}

// canonicalRekeyTo returns the rekey-to list in canonical order, or "" for an
// account without one. only_these and plus_cosigned take a list, and must have one.
func canonicalRekeyTo(params, normalized map[string]string, rekey string) (string, error) {
	_, present := params[ParameterRekeyTo]
	if rekey != RekeyOnlyThese && rekey != RekeyPlusCosigned {
		if present {
			return "", fmt.Errorf("%s needs %s=%s or %s", ParameterRekeyTo, ParameterRekeyAuthority, RekeyOnlyThese, RekeyPlusCosigned)
		}
		return "", nil
	}
	if strings.TrimSpace(normalized[ParameterRekeyTo]) == "" {
		return "", fmt.Errorf("%s=%s needs the addresses the account may be rekeyed to in %s", ParameterRekeyAuthority, rekey, ParameterRekeyTo)
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

// canonicalRecipientScope returns "" when the request names no scope. It reads
// the original request: an explicitly empty value is an error, not the default.
func canonicalRecipientScope(params map[string]string) (string, error) {
	scope, present := params[ParameterRecipientScope]
	if !present {
		return "", nil
	}
	switch scope {
	case RecipientScopeAny, RecipientScopeListed:
		return scope, nil
	default:
		return "", fmt.Errorf("%s must be %s or %s", ParameterRecipientScope, RecipientScopeListed, RecipientScopeAny)
	}
}

// canonicalUnlockRound returns "" when the request has no timelock. Zero is refused
// rather than treated as absent: it would compile a timelock every round passes.
func canonicalUnlockRound(params map[string]string) (string, error) {
	value, present := params[ParameterUnlockRound]
	if !present {
		return "", nil
	}
	round, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return "", fmt.Errorf("%s must be a positive whole number: %q", ParameterUnlockRound, value)
	}
	if round == 0 {
		return "", fmt.Errorf("%s must be positive", ParameterUnlockRound)
	}
	return strconv.FormatUint(round, 10), nil
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
