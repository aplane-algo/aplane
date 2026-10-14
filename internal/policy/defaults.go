// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	_ "embed"

	"github.com/aplane-algo/aplane/internal/noderole"
)

// The shipped defaults are the documents a new store's default.json is seeded
// from, one per node role. They are written in the policy format so the
// decoder validates them in tests and the template prints them verbatim.
//
// The signer default lets a key with no policy of its own behave like most
// signers: self-transfers and opt-ins route, every other transfer and every
// non-transfer type falls through to the operator default, a foreign rekey is
// rejected, and warning-level fields always prompt. The cosigner default
// rejects everything: a cosigner has no operator to ask and no warning
// review, so a key signs nothing until its operator writes every allowance,
// fee ceiling included.

//go:embed defaults/signer.json
var embeddedSignerDefault []byte

//go:embed defaults/cosigner.json
var embeddedCosignerDefault []byte

// SelfTransferRouteID is the ID of the signer default's one route.
const SelfTransferRouteID = "self-transfer"

// EmbeddedDefault returns a copy of the shipped default document for role.
func EmbeddedDefault(role noderole.Role) ([]byte, error) {
	switch role {
	case noderole.RoleSigner:
		return append([]byte(nil), embeddedSignerDefault...), nil
	case noderole.RoleCosigner:
		return append([]byte(nil), embeddedCosignerDefault...), nil
	default:
		return nil, unsupportedRole(role)
	}
}
