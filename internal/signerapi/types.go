// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerapi defines the signer HTTP payload types shared across the
// main module. The concrete schema now lives in pkg/signerapi so nested SDK
// modules can consume the same source of truth without maintaining a parallel
// copy.
package signerapi

import pub "github.com/aplane-algo/aplane/pkg/signerapi"

type SignRequest = pub.SignRequest
type AppCallInfo = pub.AppCallInfo
type SignResponse = pub.SignResponse
type GroupSignRequest = pub.GroupSignRequest
type CancelSignRequest = pub.CancelSignRequest
type CancelSignResponse = pub.CancelSignResponse
type RequestMode = pub.RequestMode
type SignCancelState = pub.SignCancelState
type MutationReport = pub.MutationReport
type GroupSignResponse = pub.GroupSignResponse
type GroupPlanResponse = pub.GroupPlanResponse
type GroupSimulateResponse = pub.GroupSimulateResponse
type ErrorResponse = pub.ErrorResponse
type ComponentSignRole = pub.ComponentSignRole
type ComponentSignRequest = pub.ComponentSignRequest
type ComponentSignature = pub.ComponentSignature
type ComponentSignResponse = pub.ComponentSignResponse
type AttestedAssemblyRequest = pub.AttestedAssemblyRequest
type AttestedAssemblyTarget = pub.AttestedAssemblyTarget
type AttestedPassthroughItem = pub.AttestedPassthroughItem
type AttestedAssemblyResponse = pub.AttestedAssemblyResponse
type HealthResponse = pub.HealthResponse
type StatusResponse = pub.StatusResponse
type KeyTypeInfo = pub.KeyTypeInfo
type CreationParamInfo = pub.CreationParamInfo
type InputModeInfo = pub.InputModeInfo
type RuntimeArgInfo = pub.RuntimeArgInfo
type SigningArgInfo = pub.SigningArgInfo
type KeyTypesResponse = pub.KeyTypesResponse
type KeyInfo = pub.KeyInfo
type KeysResponse = pub.KeysResponse

// KeysResult is an internal client wrapper around the /keys wire response.
// Locked is local connection state derived from a locked-signer HTTP error and
// is never part of the /keys JSON payload.
type KeysResult struct {
	pub.KeysResponse
	Locked bool
}

type AdminGenerateRequest = pub.AdminGenerateRequest
type AdminGenerateResponse = pub.AdminGenerateResponse
type AdminDeleteResponse = pub.AdminDeleteResponse
type SentryReferenceCandidate = pub.SentryReferenceCandidate
type AdminSyncSentryReferencesRequest = pub.AdminSyncSentryReferencesRequest
type SyncedSentryReferenceInfo = pub.SyncedSentryReferenceInfo
type AdminSyncSentryReferencesResponse = pub.AdminSyncSentryReferencesResponse

const (
	RequestModeSign         = pub.RequestModeSign
	RequestModePassthrough  = pub.RequestModePassthrough
	RequestModeForeign      = pub.RequestModeForeign
	SignCancelStateCanceled = pub.SignCancelStateCanceled
	SignCancelStateNotFound = pub.SignCancelStateNotFound
	ComponentSignRoleUser   = pub.ComponentSignRoleUser
	ComponentSignRoleSentry = pub.ComponentSignRoleSentry
)
