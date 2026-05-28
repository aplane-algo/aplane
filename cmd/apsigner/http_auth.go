// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
)

func authFailureReason(err error) string {
	switch err {
	case auth.ErrNoCredentials:
		return "missing_credentials"
	case auth.ErrInvalidCredentials:
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

		ident, err := fs.registryAuth.Authenticate(ctx, r)
		if err != nil {
			if fs.auditLog != nil {
				fs.auditLog.LogAuthFailed("", r.RemoteAddr, authFailureReason(err))
			}
			writeErrorJSON(w, http.StatusUnauthorized, authRequiredError(fs.registryAuth.Method()))
			return
		}

		targetResource := resource
		if targetResource.IdentityID == "" {
			targetResource.IdentityID = ident.ID
		}
		if targetResource.IdentityID != ident.ID {
			if fs.auditLog != nil {
				fs.auditLog.LogAuthFailed(ident.ID, r.RemoteAddr, "cross_identity_forbidden: "+targetResource.IdentityID)
			}
			writeErrorJSON(w, http.StatusForbidden, "Forbidden")
			return
		}

		authCtx := auth.ContextWithIdentity(ctx, ident)
		if fs.authorizer != nil {
			if err := fs.authorizer.Authorize(authCtx, ident, action, targetResource); err != nil {
				if fs.auditLog != nil {
					fs.auditLog.LogAuthFailed(ident.ID, r.RemoteAddr, "unauthorized: "+string(action))
				}
				writeErrorJSON(w, http.StatusForbidden, "Forbidden")
				return
			}
		}

		next(w, r.WithContext(authCtx))
	}
}
