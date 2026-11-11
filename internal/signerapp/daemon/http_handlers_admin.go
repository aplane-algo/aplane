// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net/http"

	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// handleAdminGenerate handles POST /admin/generate for key generation via REST.
func (fs *Signer) handleAdminGenerate(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.AdminGenerateRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	response, err := fs.restService().AdminGenerate(keyMutationAuditContext(r), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// handleAdminDelete handles DELETE /admin/keys for key deletion via REST.
func (fs *Signer) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndRuntime(fs, w, r, http.MethodDelete)
	if !ok {
		return
	}

	address := r.URL.Query().Get("address")
	response, err := fs.restService().AdminDelete(keyMutationAuditContext(r), ir, address)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// keyMutationAuditContext attributes a REST key mutation's audit events to the
// enrolled client that requested it, with its transport and remote address.
func keyMutationAuditContext(r *http.Request) context.Context {
	return signeraudit.WithAttribution(r.Context(), signingAuditAttributionFromRequest(r))
}
