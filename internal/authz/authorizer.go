// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authz

import (
	"context"
	"strings"

	"github.com/aplane-algo/aplane/internal/auth"
)

// ProductAuthorizer is the complete authorization model for the
// single-operator product. It has no mutable principal, group, grant, or target
// graph: the product admin principal has one fixed action set, and each client
// role has one fixed action set. The fingerprint identifies a credential and
// the role selects its permissions; neither is proof of authentication.
type ProductAuthorizer struct {
	allowed map[auth.Action]struct{}
	roles   map[string]map[auth.Action]struct{}
}

// NewProductSingleAuthorizer constructs the closed product authorization
// boundary. The copied maps prevent callers from mutating the package-level
// action definitions.
func NewProductSingleAuthorizer() *ProductAuthorizer {
	a := &ProductAuthorizer{
		allowed: actionSet(ProductAllowedActions()),
		roles: map[string]map[auth.Action]struct{}{
			auth.RoleClient: actionSet(ClientAllowedActions()),
		},
	}
	return a
}

func actionSet(actions []auth.Action) map[auth.Action]struct{} {
	set := make(map[auth.Action]struct{}, len(actions))
	for _, action := range actions {
		set[action] = struct{}{}
	}
	return set
}

// ClientAllowedActions returns the explicit action vocabulary granted to an
// enrolled client key over HTTP. It names the actions the authenticated HTTP
// routes expose; a new route's action remains denied until it is deliberately
// added here. Clients never receive administrative actions.
func ClientAllowedActions() []auth.Action {
	return []auth.Action{
		auth.ActionIdentityView,
		auth.ActionSignRequest,
		auth.ActionSignComponent,
		auth.ActionSignAssemble,
		auth.ActionKeysView,
		auth.ActionKeysGenerate,
		auth.ActionKeysDelete,
		auth.ActionKeyTypesView,
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
		auth.ActionCosignersView,
		auth.ActionCosignersManage,
		auth.ActionGenerationsView,
		auth.ActionGenerationQuarantinePrune,
		auth.ActionGenerationAbandonedDiscard,
		auth.ActionArchivePrune,
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
		auth.ActionClientsView,
		auth.ActionClientsEnroll,
		auth.ActionClientsRevoke,
	}
}

func (a *ProductAuthorizer) Authorize(_ context.Context, identity *auth.Identity, action auth.Action, resource auth.Resource) error {
	if identity == nil || identity.ID == "" {
		return auth.ErrUnauthorized
	}
	if !auth.IsKnownAction(action) {
		return auth.ErrForbidden
	}
	var allowed map[auth.Action]struct{}
	switch {
	case identity.ID == auth.SystemProductAdminPrincipalID:
		allowed = a.allowed
	case strings.HasPrefix(identity.ID, auth.ClientPrincipalPrefix):
		allowed = a.roles[identity.Role]
	}
	if allowed == nil {
		return auth.ErrForbidden
	}
	if _, ok := allowed[action]; !ok {
		return auth.ErrForbidden
	}
	return nil
}

var _ auth.Authorizer = (*ProductAuthorizer)(nil)
