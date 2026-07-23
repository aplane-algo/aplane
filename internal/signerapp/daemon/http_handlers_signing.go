// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"

	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

// handleSign handles the /sign endpoint for signing transactions.
// Supports single transactions and transaction groups with:
// - Automatic dummy transaction creation for large LogicSigs
// - Fee pooling across the group
// - Two-checkpoint approval (group level + per-transaction)
func (fs *Signer) handleSign(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.GroupSignRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).SignGroup(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (fs *Signer) handleBoundedAdmin(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.BoundedAdminRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).PrepareBoundedAdmin(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (fs *Signer) handleBoundedComponent(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.BoundedComponentRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}
	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).PrepareBoundedComponent(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (fs *Signer) handleBoundedAssemble(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.BoundedAssemblyRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}
	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).AssembleBounded(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleSignComponent handles the /sign/component endpoint for sentry MVP
// role-separated component signatures.
func (fs *Signer) handleSignComponent(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.ComponentSignRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).SignComponent(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleSignAssemble handles the /sign/assemble endpoint for guarded-account
// LogicSig assembly.
func (fs *Signer) handleSignAssemble(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.GuardedAssemblyRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).AssembleGuarded(r.Context(), ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleSignCancel handles explicit client cancellation for a pending /sign
// approval request. It is idempotent: a missing request may already have
// completed or been canceled through the original HTTP context.
func (fs *Signer) handleSignCancel(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.CancelSignRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	result := ir.CancelSigningApproval(req.RequestID, signerapproval.SignRequestCancelReasonClientCanceled)
	writeJSON(w, http.StatusOK, signerapi.CancelSignResponse{
		Success: true,
		State:   signCancelState(result.State),
	})
}

func signCancelState(state signerapproval.SignRequestCancelState) signerapi.SignCancelState {
	switch state {
	case signerapproval.SignRequestCancelStateCanceled:
		return signerapi.SignCancelStateCanceled
	default:
		return signerapi.SignCancelStateNotFound
	}
}

// handlePlan handles the /plan endpoint for previewing group building.
// Same input as /sign, but only executes the group-building phase:
// validates, decodes, checks keys, calculates dummies, creates dummies,
// pools fees, and computes group ID. No keys are touched, no approval flow.
func (fs *Signer) handlePlan(w http.ResponseWriter, r *http.Request) {
	ir, req, ok := decodeAuthenticatedJSONRequest[signerapi.GroupSignRequest](fs, w, r, http.MethodPost)
	if !ok {
		return
	}

	result, err := fs.restServiceWithSigningAudit(fs.signingAuditLogger(r)).Plan(ir, req)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}
