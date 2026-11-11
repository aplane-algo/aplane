// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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

// errUnknownRequestField is a request body member the endpoint's request type
// does not declare. It carries the member name for the refusal.
type errUnknownRequestField struct {
	name string
}

func (e *errUnknownRequestField) Error() string {
	return "request has unknown field " + e.name
}

var errTrailingRequestData = errors.New("request body has data after the JSON value")

// maxQuotedFieldNameBytes bounds how much of a refused member name is echoed
// back: enough to recognize a field, never a body-sized string.
const maxQuotedFieldNameBytes = 64

// decodeStrictJSON decodes one JSON request body into v. A member v does not
// declare is refused rather than dropped, at any depth, so a misspelled or
// retired field can't be silently ignored; so is anything after the value.
// Every signer HTTP endpoint that reads a body decodes it here.
func decodeStrictJSON(body io.Reader, v any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		// encoding/json reports an undeclared member only as text.
		if quoted, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			return &errUnknownRequestField{name: quoteFieldName(quoted)}
		}
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return err
		}
		return errTrailingRequestData
	}
	return nil
}

// quoteFieldName re-quotes the decoder's quoted member name as ASCII and
// bounds its length.
func quoteFieldName(quoted string) string {
	name, err := strconv.Unquote(quoted)
	if err != nil {
		name = quoted
	}
	if len(name) > maxQuotedFieldNameBytes {
		return strconv.QuoteToASCII(name[:maxQuotedFieldNameBytes]) + "..."
	}
	return strconv.QuoteToASCII(name)
}

// decodeError returns the appropriate HTTP status and message for a JSON decode error.
func decodeError(err error) (int, string) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge, "request body too large"
	}
	var unknown *errUnknownRequestField
	if errors.As(err, &unknown) {
		return http.StatusBadRequest, unknown.Error()
	}
	if errors.Is(err, errTrailingRequestData) {
		return http.StatusBadRequest, err.Error()
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
	if err := decodeStrictJSON(r.Body, &req); err != nil {
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
