// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net/http"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

// handleAdminGenerate handles POST /admin/generate for key generation via REST.
func (fs *Signer) handleAdminGenerate(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.AdminGenerateRequest](fs, w, r, http.MethodPost, func(msg string) any { return errorResponse(msg) })
	if !ok {
		return
	}

	statusCode, response := fs.restService().AdminGenerate(r.Context(), ir, req)
	if statusCode != http.StatusOK {
		writeErrorJSON(w, statusCode, response.Error)
		return
	}
	writeJSON(w, statusCode, response)
}

// handleAdminDelete handles DELETE /admin/keys for key deletion via REST.
func (fs *Signer) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndIdentity(fs, w, r, http.MethodDelete, func(msg string) any { return errorResponse(msg) })
	if !ok {
		return
	}

	address := r.URL.Query().Get("address")
	statusCode, response := fs.restService().AdminDelete(ir, address)
	if statusCode != http.StatusOK {
		writeErrorJSON(w, statusCode, response.Error)
		return
	}
	writeJSON(w, statusCode, response)
}
