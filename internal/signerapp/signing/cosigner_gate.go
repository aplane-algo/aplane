// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	cosignerComponentSignRejectMessage = "cosigner keys require /sign/component"
	guardedAccountSignRejectMessage    = "this key type requires the guarded signing flow: use POST /sign/component then POST /sign/assemble"
)

func cosignerSignRejectMessage(keyType string) (string, bool) {
	switch {
	case witness.IsKeyType(keyType):
		return cosignerComponentSignRejectMessage, true
	case keytypes.IsGuardedAccountKeyType(keyType):
		return guardedAccountSignRejectMessage, true
	default:
		return "", false
	}
}

func rejectCosignerSignKeyType(keyType string) *ServiceError {
	if msg, ok := cosignerSignRejectMessage(keyType); ok {
		return badRequest(msg)
	}
	return nil
}
