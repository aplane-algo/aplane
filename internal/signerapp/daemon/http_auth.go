// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func authFailureReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrNoCredentials):
		return "missing_credentials"
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "invalid_credentials"
	default:
		return "auth_failed"
	}
}

func authRequiredError(method string) string {
	if method == "aplane-token" {
		return "Authorization header required"
	}
	return "Authentication required"
}

// requireAuth is middleware that validates authentication and authorization
// using the configured authenticator and authorizer.
func (fs *Signer) requireAuth(action auth.Action, resource auth.Resource, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ident, err := fs.httpAuth.Authenticate(ctx, r)
		if err != nil {
			if fs.auditLog != nil {
				fs.auditLog.LogAuthFailed("", r.RemoteAddr, authFailureReason(err))
			}
			if errors.Is(err, identity.ErrNodeFailClosed) {
				writeErrorJSON(w, http.StatusServiceUnavailable, err.Error())
				return
			}
			writeErrorJSON(w, http.StatusUnauthorized, authRequiredError(fs.httpAuth.Method()))
			return
		}

		targetResource := resource
		if targetResource.IdentityID == "" {
			targetResource.IdentityID = auth.CurrentProductIdentityID()
		}
		if err := auth.RequireCurrentProductIdentity(targetResource.IdentityID); err != nil {
			if fs.auditLog != nil {
				fs.auditLog.LogAuthFailed(auth.CurrentProductIdentityID(), r.RemoteAddr, "non_product_identity_forbidden: "+targetResource.IdentityID)
			}
			writeErrorJSON(w, http.StatusForbidden, "Forbidden")
			return
		}

		authCtx := auth.ContextWithIdentity(ctx, ident)
		if fs.authorizer != nil {
			if err := fs.authorizer.Authorize(authCtx, ident, action, targetResource); err != nil {
				if fs.auditLog != nil {
					fs.auditLog.LogAuthFailed(auth.CurrentProductIdentityID(), r.RemoteAddr, "unauthorized: "+string(action))
				}
				writeErrorJSON(w, http.StatusForbidden, "Forbidden")
				return
			}
		}

		next(w, r.WithContext(authCtx))
	}
}
