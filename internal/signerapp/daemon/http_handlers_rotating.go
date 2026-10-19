// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// handleRotatingPrepare handles POST /sign/rotating/prepare.
func (fs *Signer) handleRotatingPrepare(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.RotatingPrepareRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}
	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).PrepareRotating(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleRotatingRecover handles POST /admin/rotating/recover: an operator's
// request to start or cancel a bounded search for a rotating account's live
// stage. It derives nothing itself; the stage table worker runs the grant.
func (fs *Signer) handleRotatingRecover(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.RotatingRecoverRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}
	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).RecoverRotating(keyMutationAuditContext(r), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleRotatingSign handles POST /sign/rotating/sign.
func (fs *Signer) handleRotatingSign(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.RotatingSignRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}
	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).SignRotating(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
