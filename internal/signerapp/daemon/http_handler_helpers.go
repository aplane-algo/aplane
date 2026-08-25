// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
)

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// errorCodeForStatus derives the wire error code for adapter-level failures
// that carry only an HTTP status (auth, routing, decode). Service-originated
// errors carry their own kind and use writeServiceErrorJSON instead.
func errorCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge:
		return signerapi.ErrCodeBadRequest
	case http.StatusUnauthorized:
		return signerapi.ErrCodeUnauthorized
	case http.StatusForbidden:
		return signerapi.ErrCodeForbidden
	case http.StatusNotFound:
		return signerapi.ErrCodeNotFound
	case http.StatusServiceUnavailable:
		return signerapi.ErrCodeUnavailable
	default:
		return signerapi.ErrCodeInternal
	}
}

func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, signerapi.ErrorResponse{Error: message, Code: errorCodeForStatus(status)})
}

// writeServiceErrorJSON writes a kinded service error with its stable wire
// code and mapped HTTP status.
func writeServiceErrorJSON(w http.ResponseWriter, err *svcerr.Error) {
	writeJSON(w, err.HTTPStatus(), signerapi.ErrorResponse{Error: err.Error(), Code: err.Code()})
}

// decodeError returns the appropriate HTTP status and message for a JSON decode error.
func decodeError(err error) (int, string) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge, "request body too large"
	}
	return http.StatusBadRequest, "invalid JSON"
}

func hasAuthenticatedPrincipal(r *http.Request) (int, string) {
	ident := auth.IdentityFromContext(r.Context())
	if ident == nil {
		return http.StatusUnauthorized, "no authenticated principal"
	}
	return 0, ""
}

// productRuntimeFromRequest returns the fixed product runtime for an authenticated
// principal. The principal never participates in runtime selection.
func (fs *Signer) productRuntimeFromRequest(r *http.Request) (*productruntime.Runtime, int, string) {
	if err := fs.nodeFailure(); err != nil {
		return nil, http.StatusServiceUnavailable, err.Error()
	}
	status, errMsg := hasAuthenticatedPrincipal(r)
	if errMsg != "" {
		return nil, status, errMsg
	}
	ir := fs.runtime
	if ir == nil {
		return nil, http.StatusServiceUnavailable, "product runtime unavailable"
	}
	return ir, 0, ""
}

func authenticatedRuntime(fs *Signer, w http.ResponseWriter, r *http.Request) (*productruntime.Runtime, bool) {
	ir, status, errMsg := fs.productRuntimeFromRequest(r)
	if errMsg != "" {
		writeErrorJSON(w, status, errMsg)
		return nil, false
	}
	return ir, true
}

func decodeAuthenticatedJSONRequest[Req any](fs *Signer, w http.ResponseWriter, r *http.Request, method string) (*productruntime.Runtime, Req, bool) {
	var zero Req
	if r.Method != method {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "Method not allowed")
		return nil, zero, false
	}

	ir, ok := authenticatedRuntime(fs, w, r)
	if !ok {
		return nil, zero, false
	}

	var req Req
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status, msg := decodeError(err)
		writeErrorJSON(w, status, msg)
		return nil, zero, false
	}

	return ir, req, true
}

func requireMethodAndRuntime(fs *Signer, w http.ResponseWriter, r *http.Request, method string) (*productruntime.Runtime, bool) {
	if r.Method != method {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "Method not allowed")
		return nil, false
	}
	return authenticatedRuntime(fs, w, r)
}
