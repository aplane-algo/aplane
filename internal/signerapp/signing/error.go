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
	ErrorBadRequest               = svcerr.KindBadRequest
	ErrorForbidden                = svcerr.KindForbidden
	ErrorLocked                   = svcerr.KindLocked
	ErrorUnavailable              = svcerr.KindUnavailable
	ErrorInternal                 = svcerr.KindInternal
	ErrorCosignerRequired         = svcerr.KindCosignerRequired
	ErrorRekeyTargetNotListed     = svcerr.KindRekeyTargetNotListed
	ErrorRotatingSigningRequired  = svcerr.KindRotatingSigningRequired
	ErrorRotatingStageUnproven    = svcerr.KindRotatingStageUnproven
	ErrorRotatingStageChanged     = svcerr.KindRotatingStageChanged
	ErrorRotatingWindowNotCurrent = svcerr.KindRotatingWindowNotCurrent
	ErrorRekeyTargetNotValid      = svcerr.KindRekeyTargetNotValid
)

func badRequest(msg string) *ServiceError { return &ServiceError{Kind: ErrorBadRequest, Message: msg} }
func forbidden(msg string) *ServiceError  { return &ServiceError{Kind: ErrorForbidden, Message: msg} }
func unavailable(msg string) *ServiceError {
	return &ServiceError{Kind: ErrorUnavailable, Message: msg}
}
func internal(msg string) *ServiceError { return &ServiceError{Kind: ErrorInternal, Message: msg} }

// cosignerRequired rejects a cosigner-gated bounded spend submitted on the
// plain /sign path and directs clients to the user-first component flow.
func cosignerRequired() *ServiceError {
	return &ServiceError{
		Kind:    ErrorCosignerRequired,
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

// lockedMessage is the locked error's text, which errKeyUseRefused shares.
const lockedMessage = "signer is locked"

// lockedError reports the signer keystore as locked with the dedicated
// machine-readable kind.
func lockedError() *ServiceError {
	return &ServiceError{Kind: ErrorLocked, Message: lockedMessage}
}

// sessionEndedError answers a request whose approval was withdrawn because
// the signer's session ended while it waited (a lock, recovery, or store
// maintenance). It is a locked error: the request can be sent again.
func sessionEndedError() *ServiceError {
	return &ServiceError{Kind: ErrorLocked, Message: "the signer's session ended while the request waited for approval; send it again"}
}

// approverGoneError answers a request whose prompt was withdrawn because the
// apadmin session it was shown to disconnected or was replaced before
// answering. Nobody rejected it: like a request that finds no apadmin
// connected, it is unavailable, and it can be sent again.
func approverGoneError(displaced bool) *ServiceError {
	if displaced {
		return unavailable("another apadmin session replaced the one showing the approval before it was answered; send the request again")
	}
	return unavailable("apadmin disconnected before answering the approval; send the request again once an apadmin session is connected")
}
