// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import "github.com/aplane-algo/aplane/internal/sentry/keytypes"

const (
	sentryComponentSignRejectMessage = "sentry component keys require /sign/component"
	guardedAccountSignRejectMessage  = "this key type requires the guarded signing flow: use POST /sign/component then POST /sign/assemble"
)

func sentrySignRejectMessage(keyType string) (string, bool) {
	switch {
	case keytypes.IsSentryComponentKeyType(keyType):
		return sentryComponentSignRejectMessage, true
	case keytypes.IsGuardedAccountKeyType(keyType):
		return guardedAccountSignRejectMessage, true
	default:
		return "", false
	}
}

func rejectSentrySignKeyType(keyType string) *ServiceError {
	if msg, ok := sentrySignRejectMessage(keyType); ok {
		return badRequest(msg)
	}
	return nil
}
