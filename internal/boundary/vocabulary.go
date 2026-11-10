// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundary is the family-neutral vocabulary of the plain hosts' bounds
// and overlays: the boundary file grammar, presets, and receipt. Clients use it
// to build and review requests. The provider that turns a request into a program
// lives in lsig/plainhost.
package boundary

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

const (
	// SchemaV1 identifies the boundary file grammar.
	SchemaV1 = "aplane.boundary.v1"

	// Creation parameter names. The first three select a shape; recipients is the
	// parameter a shape's composer declares besides its authority keys.
	ParameterSpendEffects   = "spend_effects"
	ParameterRekeyAuthority = "rekey_authority"
	ParameterListEncoding   = "list_encoding"
	ParameterRecipients     = "recipients"
	// ParameterRecipientScope selects whether the account has a recipient rule.
	// Absent means listed, so leaving out a list still fails closed; "any" must be
	// asked for, and selects a limits-only account: the fee ceiling and transfer
	// kinds, with no recipient list.
	ParameterRecipientScope = "recipient_scope"
	// ParameterMaxFee is a bounded account's fee ceiling per transaction, in
	// microAlgos. Absent means DefaultMaxFee.
	ParameterMaxFee = "max_fee"
	// ParameterRekeyTo is a rekey-to list's addresses, required with
	// rekey_authority=only_these or plus_cosigned and refused otherwise.
	ParameterRekeyTo = boundedmeta.RekeyListEntriesParameter
	// ParameterCosigner is the signer-side reference selector. It is resolved to
	// a public key before an instance is selected.
	ParameterCosigner = "cosigner"

	// DefaultMaxFee is the fee ceiling of a bounded account whose request names
	// none, in microAlgos.
	DefaultMaxFee uint64 = 10_000

	EncodingAuto   = "auto"
	EncodingInline = "inline"
	EncodingMerkle = "merkle"

	RecipientScopeListed = "listed"
	RecipientScopeAny    = "any"

	// RekeySpendingKey lets the spending key rekey the account, with the cosigner
	// on a cosigned account. RekeyOnlyThese lets the spending key alone rekey it
	// only to an address on its rekey-to list. RekeyPlusCosigned, on a cosigned
	// account, lets the spending key alone rekey it to a listed address and, with
	// the cosigner, to any other. RekeyRefused gives an account no rekey path at
	// all: its only way out is what it may spend or close.
	RekeySpendingKey  = string(boundedmeta.RekeySpendingKey)
	RekeyOnlyThese    = boundedmeta.RekeyOnlyThese
	RekeyPlusCosigned = boundedmeta.RekeyPlusCosigned
	RekeyRefused      = string(boundedmeta.RekeyRefused)
)

// DefaultMaxFeeText is DefaultMaxFee as a request or a file writes it.
var DefaultMaxFeeText = strconv.FormatUint(DefaultMaxFee, 10)

// ParseMaxFee reads a fee ceiling. Only the plain decimal form is accepted: a
// leading zero or a sign would read differently elsewhere, as YAML reads 010 as
// octal. Any value the wire can carry is valid, zero included: an account that
// can't pay its own fees still works with another account paying them.
func ParseMaxFee(value string) (uint64, error) {
	text := strings.TrimSpace(value)
	fee, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(fee, 10) != text {
		return 0, fmt.Errorf("%s must be a whole number of microAlgos: %q", ParameterMaxFee, value)
	}
	if fee > boundedmeta.MaxFeeLimit {
		return 0, fmt.Errorf("%s %d is above %d, the largest value every client reads exactly", ParameterMaxFee, fee, boundedmeta.MaxFeeLimit)
	}
	return fee, nil
}
