// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import "net/http"

type ErrorKind string

const (
	ErrorBadRequest  ErrorKind = "bad_request"
	ErrorForbidden   ErrorKind = "forbidden"
	ErrorUnavailable ErrorKind = "unavailable"
	ErrorInternal    ErrorKind = "internal"
)

type ServiceError struct {
	Kind    ErrorKind
	Message string
}

func (e *ServiceError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *ServiceError) HTTPStatus() int {
	if e == nil {
		return 0
	}
	switch e.Kind {
	case ErrorBadRequest:
		return http.StatusBadRequest
	case ErrorForbidden:
		return http.StatusForbidden
	case ErrorUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func badRequest(msg string) *ServiceError { return &ServiceError{Kind: ErrorBadRequest, Message: msg} }
func forbidden(msg string) *ServiceError  { return &ServiceError{Kind: ErrorForbidden, Message: msg} }
func unavailable(msg string) *ServiceError {
	return &ServiceError{Kind: ErrorUnavailable, Message: msg}
}
func internal(msg string) *ServiceError { return &ServiceError{Kind: ErrorInternal, Message: msg} }
