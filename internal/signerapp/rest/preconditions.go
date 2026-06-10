// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

// ensureSignable runs the preconditions shared by every signing-family
// endpoint: a usable identity runtime that is neither decommissioned nor
// locked. It also defaults a nil context for endpoints that thread one
// through. Role gates and dependency checks remain per-endpoint.
func ensureSignable(ctx context.Context, ir *identity.Runtime) (context.Context, *signersigning.ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return ctx, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "identity runtime is nil"}
	}
	if ir.IsDecommissioned() {
		return ctx, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: identity.ErrDecommissioned.Error()}
	}
	if !ir.IsUnlocked() {
		return ctx, &signersigning.ServiceError{Kind: signersigning.ErrorLocked, Message: "signer is locked"}
	}
	return ctx, nil
}

// notConfigured reports a missing service dependency on a REST endpoint.
func notConfigured(what string) *signersigning.ServiceError {
	return &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: what + " not configured"}
}
