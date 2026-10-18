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
	ErrorBadRequest                 = svcerr.KindBadRequest
	ErrorForbidden                  = svcerr.KindForbidden
	ErrorLocked                     = svcerr.KindLocked
	ErrorUnavailable                = svcerr.KindUnavailable
	ErrorInternal                   = svcerr.KindInternal
	ErrorBoundedAdminRequired       = svcerr.KindBoundedAdminRequired
	ErrorBoundedCosignerRequired    = svcerr.KindBoundedCosignerRequired
	ErrorBoundedAdminTargetRejected = svcerr.KindBoundedAdminTargetRejected
	ErrorRotatingSigningRequired    = svcerr.KindRotatingSigningRequired
	ErrorRotatingStageUnproven      = svcerr.KindRotatingStageUnproven
	ErrorRotatingStageChanged       = svcerr.KindRotatingStageChanged
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

// boundedAdminTargetRejected refuses an admin-key bounded rekey whose target
// is not a nonrotating signing credential this signer holds. The rule and its
// two checks are described in bounded_admin_target.go.
func boundedAdminTargetRejected(msg string) *ServiceError {
	return &ServiceError{Kind: ErrorBoundedAdminTargetRejected, Message: msg}
}

// boundedCosignerRequired rejects a cosigner-gated bounded spend submitted on the
// plain /sign path and directs clients to the user-first component flow.
func boundedCosignerRequired() *ServiceError {
	return &ServiceError{
		Kind:    ErrorBoundedCosignerRequired,
		Message: "bounded-cosigner operation requires POST /plan, POST /sign/component, then POST /sign/assemble",
	}
}

// rotatingSigningRequired rejects a rotating account submitted to an ordinary
// signing endpoint. Its stage program changes on every spend, so only the
// rotating flow can prepare and sign for it.
func rotatingSigningRequired() *ServiceError {
	return &ServiceError{
		Kind:    ErrorRotatingSigningRequired,
		Message: "rotating account requires POST /sign/rotating/prepare, then POST /sign/rotating/sign",
	}
}

// lockedError reports the signer keystore as locked with the dedicated
// machine-readable kind.
func lockedError() *ServiceError {
	return &ServiceError{Kind: ErrorLocked, Message: "signer is locked"}
}
