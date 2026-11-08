// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/aplane-algo/aplane/internal/witness"
)

const cosignerComponentSignRejectMessage = "cosigner keys require /sign/component"

// cosignerSignRejectMessage refuses ordinary /sign for a witness key, which
// signs only cosigner components. A cosigned account is refused by its stored
// metadata (execution.go), not by its key type.
func cosignerSignRejectMessage(keyType string) (string, bool) {
	if witness.IsKeyType(keyType) {
		return cosignerComponentSignRejectMessage, true
	}
	return "", false
}

func rejectCosignerSignKeyType(keyType string) *ServiceError {
	if msg, ok := cosignerSignRejectMessage(keyType); ok {
		return badRequest(msg)
	}
	return nil
}
