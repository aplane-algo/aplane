// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import "github.com/aplane-algo/aplane/internal/signerapp/svcerr"

// ServiceError aliases the unified signer service-error model so kinds map
// onto stable wire codes and HTTP status in one place.
type (
	ErrorKind    = svcerr.Kind
	ServiceError = svcerr.Error
)

const (
	ErrorBadRequest            = svcerr.KindBadRequest
	ErrorForbidden             = svcerr.KindForbidden
	ErrorLocked                = svcerr.KindLocked
	ErrorUnavailable           = svcerr.KindUnavailable
	ErrorInternal              = svcerr.KindInternal
	ErrorBoundedAdminRequired  = svcerr.KindBoundedAdminRequired
	ErrorBoundedSentryRequired = svcerr.KindBoundedSentryRequired
)

func badRequest(msg string) *ServiceError { return &ServiceError{Kind: ErrorBadRequest, Message: msg} }
func forbidden(msg string) *ServiceError  { return &ServiceError{Kind: ErrorForbidden, Message: msg} }
func unavailable(msg string) *ServiceError {
	return &ServiceError{Kind: ErrorUnavailable, Message: msg}
}
func internal(msg string) *ServiceError { return &ServiceError{Kind: ErrorInternal, Message: msg} }

// boundedAdminRequired rejects an admin-key bounded operation submitted on the
// plain /sign path with the machine-readable code clients route on to redirect
// the operation to POST /sign/bounded-admin.
func boundedAdminRequired() *ServiceError {
	return &ServiceError{Kind: ErrorBoundedAdminRequired, Message: "Falcon-admin bounded operation requires POST /sign/bounded-admin"}
}

// boundedSentryRequired rejects a sentry-gated bounded spend submitted on the
// plain /sign path and directs clients to the user-first component flow.
func boundedSentryRequired() *ServiceError {
	return &ServiceError{
		Kind:    ErrorBoundedSentryRequired,
		Message: "bounded-sentry operation requires POST /plan, POST /sign/component, then POST /sign/assemble",
	}
}

// lockedError reports the signer keystore as locked with the dedicated
// machine-readable kind.
func lockedError() *ServiceError {
	return &ServiceError{Kind: ErrorLocked, Message: "signer is locked"}
}
