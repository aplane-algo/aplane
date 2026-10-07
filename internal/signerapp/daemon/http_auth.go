// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
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

// authRequiredError is the response body for an unauthenticated request. A
// request is authenticated by its connection, so there is no header to ask
// for: a client that reaches this did not arrive through an enrolled SSH
// connection.
func authRequiredError(string) string {
	return "Authentication required: connect through an enrolled SSH key"
}

// requireAuth is middleware that validates authentication and authorization
// using the configured authenticator and authorizer.
func (fs *Signer) requireAuth(action auth.Action, resource auth.Resource, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ident, err := fs.httpAuth.Authenticate(ctx, r)
		if err == nil && ident == nil {
			err = auth.ErrInvalidCredentials
		}
		if err != nil {
			if fs.auditLog != nil {
				fs.auditLog.LogAuthFailed(r.RemoteAddr, authFailureReason(err))
			}
			if errors.Is(err, productruntime.ErrNodeFailClosed) {
				writeErrorJSON(w, http.StatusServiceUnavailable, err.Error())
				return
			}
			writeErrorJSON(w, http.StatusUnauthorized, authRequiredError(fs.httpAuth.Method()))
			return
		}

		authCtx := auth.ContextWithIdentity(ctx, ident)
		if fs.authorizer != nil {
			if err := fs.authorizer.Authorize(authCtx, ident, action, resource); err != nil {
				if fs.auditLog != nil {
					fs.auditLog.LogAuthFailedAttributed(ident.ID, r.RemoteAddr, "unauthorized: "+string(action))
				}
				writeErrorJSON(w, http.StatusForbidden, "Forbidden")
				return
			}
		}

		// An authenticated client may keep its connection alive.
		w.Header().Del("Connection")
		next(w, r.WithContext(authCtx))
	}
}
