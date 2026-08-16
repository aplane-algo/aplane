// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authz

import (
	"context"

	"github.com/aplane-algo/aplane/internal/auth"
)

const SystemProductAdminPrincipalID = "system:product-admin"

// ProductAuthorizer is the complete authorization model for the
// single-operator product. It has no mutable principal, group, grant, or target
// graph: every decision is an exact principal, action, and product-resource
// check.
type ProductAuthorizer struct {
	allowed map[auth.Action]struct{}
}

// NewProductSingleAuthorizer constructs the closed product authorization
// boundary. The copied map prevents callers from mutating the package-level
// action definition.
func NewProductSingleAuthorizer() *ProductAuthorizer {
	a := &ProductAuthorizer{allowed: make(map[auth.Action]struct{}, len(ProductAllowedActions()))}
	for _, action := range ProductAllowedActions() {
		a.allowed[action] = struct{}{}
	}
	return a
}

// NewProductPrincipalIdentity creates the reserved product principal used by
// authenticated HTTP and admin sessions.
func NewProductPrincipalIdentity(method string) *auth.Identity {
	return &auth.Identity{
		ID:     SystemProductAdminPrincipalID,
		Type:   "system",
		Method: method,
	}
}

// ProductAllowedActions returns the explicit action vocabulary granted to the
// product admin. A newly registered known action remains denied until it is
// deliberately added here.
func ProductAllowedActions() []auth.Action {
	return []auth.Action{
		auth.ActionIdentityView,
		auth.ActionIdentityUnlock,
		auth.ActionIdentityBackup,
		auth.ActionIdentityRestore,
		auth.ActionIdentityLock,
		auth.ActionIdentityPassphrase,
		auth.ActionSignRequest,
		auth.ActionSignApprove,
		auth.ActionSignComponent,
		auth.ActionSignAssemble,
		auth.ActionKeysView,
		auth.ActionKeysGenerate,
		auth.ActionKeysImport,
		auth.ActionKeysExport,
		auth.ActionKeysDelete,
		auth.ActionSentriesSync,
		auth.ActionSentriesView,
		auth.ActionSentriesManage,
		auth.ActionGenerationsView,
		auth.ActionKeyTypesView,
		auth.ActionKeyTypesActivate,
		auth.ActionKeyTypesDeactivate,
		auth.ActionTemplatesView,
		auth.ActionTemplatesInstall,
		auth.ActionTemplatesRemove,
		auth.ActionPolicyView,
		auth.ActionPolicyUpdate,
		auth.ActionSettingsView,
		auth.ActionSettingsUpdate,
		auth.ActionTokenProvision,
		auth.ActionTokenRevoke,
	}
}

func (a *ProductAuthorizer) Authorize(_ context.Context, identity *auth.Identity, action auth.Action, resource auth.Resource) error {
	if identity == nil || identity.ID == "" {
		return auth.ErrUnauthorized
	}
	if identity.ID != SystemProductAdminPrincipalID {
		return auth.ErrForbidden
	}
	if !auth.IsKnownAction(action) {
		return auth.ErrForbidden
	}
	if _, ok := a.allowed[action]; !ok {
		return auth.ErrForbidden
	}
	if resource.IdentityID != "" && !auth.IsCurrentProductIdentity(resource.IdentityID) {
		return auth.ErrForbidden
	}
	return nil
}

var _ auth.Authorizer = (*ProductAuthorizer)(nil)
