// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net/http"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// handleAdminGenerate handles POST /admin/generate for key generation via REST.
func (fs *Signer) handleAdminGenerate(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.AdminGenerateRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	response, err := fs.restService().AdminGenerate(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// handleAdminSyncSentries handles POST /admin/sentries/sync for public
// sentry reference catalog sync via REST.
func (fs *Signer) handleAdminSyncSentries(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.AdminSyncSentryReferencesRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	response, err := fs.restService().AdminSyncSentryReferences(ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	if response.Added > 0 || response.Updated > 0 || response.Removed > 0 {
		if hub := fs.adminHub(); hub != nil {
			hub.NotifyKeysChanged(ir.ID(), adminproto.KeysChangedNotification{KeyCount: ir.KeyCount()})
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// handleAdminDelete handles DELETE /admin/keys for key deletion via REST.
func (fs *Signer) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndIdentity(fs, w, r, http.MethodDelete)
	if !ok {
		return
	}

	address := r.URL.Query().Get("address")
	response, err := fs.restService().AdminDelete(ir, address)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
