// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package svcerr is the single kinded service-error model for signer-side
// application services. Kinds map one-to-one onto the stable wire codes in
// pkg/signerapi and onto HTTP status at the adapter edge, so error message
// wording never needs to carry machine meaning.
package svcerr

import (
	"net/http"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// Kind classifies a service error. The string value is the wire code.
type Kind string

const (
	KindBadRequest            Kind = signerapi.ErrCodeBadRequest
	KindUnauthorized          Kind = signerapi.ErrCodeUnauthorized
	KindForbidden             Kind = signerapi.ErrCodeForbidden
	KindLocked                Kind = signerapi.ErrCodeLocked
	KindNotFound              Kind = signerapi.ErrCodeNotFound
	KindInvalidPassphrase     Kind = signerapi.ErrCodeInvalidPassphrase
	KindUnavailable           Kind = signerapi.ErrCodeUnavailable
	KindCacheRefresh          Kind = signerapi.ErrCodeCacheRefresh
	KindInternal              Kind = signerapi.ErrCodeInternal
	KindBoundedAdminRequired  Kind = signerapi.ErrCodeBoundedAdminRequired
	KindBoundedSentryRequired Kind = signerapi.ErrCodeBoundedSentryRequired
)

// HTTPStatus maps a kind to its HTTP status. Unknown kinds map to 500.
func (k Kind) HTTPStatus() int {
	switch k {
	case KindBadRequest, KindBoundedAdminRequired, KindBoundedSentryRequired:
		return http.StatusBadRequest
	case KindUnauthorized:
		return http.StatusUnauthorized
	case KindForbidden, KindLocked, KindInvalidPassphrase:
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Error is a kinded service error.
type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// HTTPStatus returns the HTTP status for the error's kind.
func (e *Error) HTTPStatus() int {
	if e == nil {
		return 0
	}
	return e.Kind.HTTPStatus()
}

// Code returns the stable wire code for the error's kind.
func (e *Error) Code() string {
	if e == nil {
		return ""
	}
	return string(e.Kind)
}
