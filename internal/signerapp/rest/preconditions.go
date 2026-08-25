// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
)

// ensureRuntimeUnlocked enforces the runtime precondition shared by REST
// operations that require access to unlocked product state.
func ensureRuntimeUnlocked(ir *productruntime.Runtime) *svcerr.Error {
	if ir == nil {
		return &svcerr.Error{Kind: svcerr.KindInternal, Message: "product runtime is nil"}
	}
	if !ir.IsUnlocked() {
		return &svcerr.Error{Kind: svcerr.KindLocked, Message: "signer is locked"}
	}
	return nil
}

// ensureSignable runs the preconditions shared by every signing-family
// endpoint: a usable, unlocked product runtime. It also defaults a nil
// context for endpoints that thread one
// through. Role gates and dependency checks remain per-endpoint.
func ensureSignable(ctx context.Context, ir *productruntime.Runtime) (context.Context, *signersigning.ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return ctx, err
	}
	return ctx, nil
}

// notConfigured reports a missing service dependency on a REST endpoint.
func notConfigured(what string) *signersigning.ServiceError {
	return &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: what + " not configured"}
}
