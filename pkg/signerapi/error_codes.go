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
)
