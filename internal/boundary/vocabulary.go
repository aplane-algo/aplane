// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundary is the family-neutral vocabulary of the general bounded key
// type: its boundary file grammar, presets, and receipt. Clients use it to build
// and review requests. The provider that turns a request into a program lives in
// lsig/boundedaccount.
package boundary

import "github.com/aplane-algo/aplane/internal/boundedmeta"

const (
	// KeyTypeV1 is the general bounded key type.
	KeyTypeV1 = "aplane.falcon1024-b.v1"

	// SchemaV1 identifies the boundary file grammar.
	SchemaV1 = "aplane.boundary.v1"

	// Creation parameter names. The first three select a shape; recipients is the
	// parameter a shape's composer declares besides its authority keys.
	ParameterSpendEffects   = "spend_effects"
	ParameterRekeyAuthority = "rekey_authority"
	ParameterListEncoding   = "list_encoding"
	ParameterRecipients     = "recipients"
	// ParameterUnlockRound is the first round the account can spend. A round
	// compiles the same way everywhere but means a different time on each network.
	ParameterUnlockRound = "unlock_round"
	// ParameterCosigner is the signer-side reference selector. It is resolved to
	// a public key before an instance is selected.
	ParameterCosigner = "cosigner"

	EncodingAuto   = "auto"
	EncodingInline = "inline"
	EncodingMerkle = "merkle"

	// RekeySpendingKey lets the spending key rekey the account. RekeyRefused gives
	// the account no rekey path at all; the stored contract has no rekey operation.
	RekeySpendingKey = boundedmeta.AdminAuthorizationSpend
	RekeyRefused     = "refused"
)
