// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

// Machine-readable error codes carried in ErrorResponse.Code.
//
// These values are a stable wire contract: clients and SDKs branch on them
// instead of matching error message text. New codes may be added; existing
// values must not change meaning. An empty code means the server predates
// code support or the failure had no specific classification.
const (
	// ErrCodeBadRequest covers malformed or invalid request input.
	ErrCodeBadRequest = "bad_request"
	// ErrCodeUnauthorized covers missing or invalid authentication.
	ErrCodeUnauthorized = "unauthorized"
	// ErrCodeForbidden covers authenticated requests the signer refuses,
	// including policy rejections and role/identity restrictions.
	ErrCodeForbidden = "forbidden"
	// ErrCodeLocked indicates the signer keystore is locked.
	ErrCodeLocked = "locked"
	// ErrCodeNotFound covers unknown keys or resources.
	ErrCodeNotFound = "not_found"
	// ErrCodeInvalidPassphrase covers passphrase verification failures.
	ErrCodeInvalidPassphrase = "invalid_passphrase"
	// ErrCodeUnavailable covers temporary inability to serve the request.
	ErrCodeUnavailable = "unavailable"
	// ErrCodeCacheRefresh indicates the operation mutated the store but the
	// signer key cache failed to refresh afterward.
	ErrCodeCacheRefresh = "cache_refresh"
	// ErrCodeInternal covers unexpected server-side failures.
	ErrCodeInternal = "internal"
	// ErrCodeBoundedAdminRequired directs contract-admin operations to the
	// external bounded-admin completion flow.
	ErrCodeBoundedAdminRequired = "bounded_admin_required"
	// ErrCodeBoundedCosignerRequired directs cosigner-gated bounded spends to the
	// bounded component and assembly flow.
	ErrCodeBoundedCosignerRequired = "bounded_cosigner_required"
	// ErrCodeBoundedAdminTargetRejected refuses an admin-key bounded rekey
	// whose target is not a nonrotating signing credential this signer holds.
	// Admin rekeys may only move an account to a credential in the signer's
	// own store; leaving APlane custody is a separate ordinary rekey from
	// that credential.
	ErrCodeBoundedAdminTargetRejected = "bounded_admin_target_rejected"
	// ErrCodeRotatingSigningRequired directs rotating accounts to the rotating
	// prepare and sign flow.
	ErrCodeRotatingSigningRequired = "rotating_signing_required"
	// ErrCodeRotatingStageUnproven reports that the signer has not yet found
	// the rotating account's live stage; its background scan continues and a
	// retry usually succeeds.
	ErrCodeRotatingStageUnproven = "rotating_stage_unproven"
	// ErrCodeRotatingStageChanged reports that the account's authorizer moved
	// between preparing and signing; nothing was signed and the client should
	// rebuild the transaction and prepare again.
	ErrCodeRotatingStageChanged = "rotating_stage_changed"
)
