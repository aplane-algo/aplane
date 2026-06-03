// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authz

import (
	"context"

	"github.com/aplane-algo/aplane/internal/auth"
)

const (
	SystemProductAdminPrincipalID = "system:product-admin"
	SystemProductAdminsGroupID    = "system:product-admins"

	subjectPrincipalPrefix = "principal:"
	subjectGroupPrefix     = "group:"
	targetAnyIdentity      = "*"
)

// PrincipalResolver maps an authenticated credential identity onto the
// authorization principal that should be evaluated.
type PrincipalResolver func(identity *auth.Identity) (string, bool)

// Principal is an authorization subject that can authenticate or be mapped from
// a compatibility credential.
type Principal struct {
	ID       string
	Type     string
	Disabled bool
}

// Group is a collection of principals. Membership alone grants nothing.
type Group struct {
	ID       string
	Members  []string
	Disabled bool
}

// Grant binds one principal or group subject to actions on a target identity.
type Grant struct {
	Subject    string
	IdentityID string
	Actions    []auth.Action
	Disabled   bool
}

// Config defines the in-memory authorization graph used by Authorizer.
type Config struct {
	Principals []Principal
	Groups     []Group
	Grants     []Grant
	Resolve    PrincipalResolver
}

// Authorizer evaluates authorization using principals, groups, and grants.
type Authorizer struct {
	principals map[string]Principal
	groups     map[string]Group
	grants     []Grant
	resolve    PrincipalResolver
}

// NewAuthorizer creates a grant-backed authorizer. Unknown principals, disabled
// principals, disabled groups, missing grants, and unknown actions fail closed.
func NewAuthorizer(cfg Config) *Authorizer {
	a := &Authorizer{
		principals: make(map[string]Principal, len(cfg.Principals)),
		groups:     make(map[string]Group, len(cfg.Groups)),
		grants:     append([]Grant(nil), cfg.Grants...),
		resolve:    cfg.Resolve,
	}
	if a.resolve == nil {
		a.resolve = identityPrincipalResolver
	}
	for _, principal := range cfg.Principals {
		if principal.ID != "" {
			a.principals[principal.ID] = principal
		}
	}
	for _, group := range cfg.Groups {
		if group.ID != "" {
			group.Members = append([]string(nil), group.Members...)
			a.groups[group.ID] = group
		}
	}
	return a
}

// NewProductSingleAuthorizer returns the first-rollout authorization model: all
// compatibility credentials map to one reserved system principal, and that
// principal is authorized only by explicit bootstrap grants.
func NewProductSingleAuthorizer() *Authorizer {
	return NewAuthorizer(Config{
		Principals: []Principal{{
			ID:   SystemProductAdminPrincipalID,
			Type: "system",
		}},
		Groups: []Group{{
			ID:      SystemProductAdminsGroupID,
			Members: []string{SystemProductAdminPrincipalID},
		}},
		Grants: []Grant{{
			Subject:    GroupSubject(SystemProductAdminsGroupID),
			IdentityID: targetAnyIdentity,
			Actions:    ProductBootstrapActions(),
		}},
		Resolve: productPrincipalResolver,
	})
}

// NewProductPrincipalIdentity creates the reserved product principal used by
// admin sessions in the constrained product mode.
func NewProductPrincipalIdentity(method string) *auth.Identity {
	return &auth.Identity{
		ID:     SystemProductAdminPrincipalID,
		Type:   "system",
		Method: method,
	}
}

// PrincipalSubject returns the canonical grant subject for a principal ID.
func PrincipalSubject(id string) string {
	return subjectPrincipalPrefix + id
}

// GroupSubject returns the canonical grant subject for a group ID.
func GroupSubject(id string) string {
	return subjectGroupPrefix + id
}

// ProductBootstrapActions returns the stable action vocabulary granted to the
// product bootstrap principal. The list is explicit so unknown actions fail
// closed instead of being accepted by a wildcard.
func ProductBootstrapActions() []auth.Action {
	return []auth.Action{
		auth.ActionIdentityView,
		auth.ActionIdentityUnlock,
		auth.ActionIdentityBackup,
		auth.ActionIdentityRestore,
		auth.ActionIdentityLock,
		auth.ActionIdentityPassphrase,
		auth.ActionIdentityDecommission,
		auth.ActionSignRequest,
		auth.ActionSignApprove,
		auth.ActionSignComponent,
		auth.ActionSignAssemble,
		auth.ActionKeysView,
		auth.ActionKeysGenerate,
		auth.ActionKeysImport,
		auth.ActionKeysExport,
		auth.ActionKeysDelete,
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

func (a *Authorizer) Authorize(ctx context.Context, identity *auth.Identity, action auth.Action, resource auth.Resource) error {
	_ = ctx
	if identity == nil {
		return auth.ErrUnauthorized
	}
	if !auth.IsKnownAction(action) {
		return auth.ErrForbidden
	}
	principalID, ok := a.resolve(identity)
	if !ok || principalID == "" {
		return auth.ErrUnauthorized
	}
	principal, ok := a.principals[principalID]
	if !ok || principal.Disabled {
		return auth.ErrForbidden
	}

	targetIdentityID := resource.IdentityID
	if targetIdentityID == "" {
		targetIdentityID = identity.ID
	}
	subjects := map[string]struct{}{
		PrincipalSubject(principalID): {},
	}
	for _, group := range a.groups {
		if group.Disabled || !containsString(group.Members, principalID) {
			continue
		}
		subjects[GroupSubject(group.ID)] = struct{}{}
	}

	for _, grant := range a.grants {
		if grant.Disabled || !grantTargetsIdentity(grant.IdentityID, targetIdentityID) {
			continue
		}
		if _, ok := subjects[grant.Subject]; !ok {
			continue
		}
		if containsAction(grant.Actions, action) {
			return nil
		}
	}
	return auth.ErrForbidden
}

func identityPrincipalResolver(identity *auth.Identity) (string, bool) {
	if identity == nil || identity.ID == "" {
		return "", false
	}
	return identity.ID, true
}

func productPrincipalResolver(identity *auth.Identity) (string, bool) {
	if identity == nil || identity.ID == "" {
		return "", false
	}
	return SystemProductAdminPrincipalID, true
}

func grantTargetsIdentity(grantIdentityID, targetIdentityID string) bool {
	return grantIdentityID == targetAnyIdentity || grantIdentityID == targetIdentityID
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsAction(items []auth.Action, want auth.Action) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

var _ auth.Authorizer = (*Authorizer)(nil)
