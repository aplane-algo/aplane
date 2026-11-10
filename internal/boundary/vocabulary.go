// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundary is the family-neutral vocabulary of the plain hosts' bounds
// and overlays: the boundary file grammar, presets, and receipt. Clients use it
// to build and review requests. The provider that turns a request into a program
// lives in lsig/plainhost.
package boundary

import "github.com/aplane-algo/aplane/internal/boundedmeta"

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
	// ParameterRekeyTo is a rekey-to list's addresses, required with
	// rekey_authority=only_these or plus_cosigned and refused otherwise.
	ParameterRekeyTo = boundedmeta.RekeyListEntriesParameter
	// ParameterCosigner is the signer-side reference selector. It is resolved to
	// a public key before an instance is selected.
	ParameterCosigner = "cosigner"

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
