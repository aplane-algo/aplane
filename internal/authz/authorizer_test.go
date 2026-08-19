// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
)

func TestProductAuthorizer(t *testing.T) {
	authorizer := NewProductSingleAuthorizer()
	product := NewProductPrincipalIdentity("ipc-passphrase")

	for _, tc := range []struct {
		name     string
		identity *auth.Identity
		action   auth.Action
		resource auth.Resource
		wantErr  error
	}{
		{name: "explicit action and resource", identity: product, action: auth.ActionKeysGenerate, resource: auth.Resource{Type: "key"}},
		{name: "nil principal", action: auth.ActionKeysView, wantErr: auth.ErrUnauthorized},
		{name: "empty principal", identity: &auth.Identity{}, action: auth.ActionKeysView, wantErr: auth.ErrUnauthorized},
		{name: "unknown principal", identity: &auth.Identity{ID: "default"}, action: auth.ActionKeysView, wantErr: auth.ErrForbidden},
		{name: "unknown action", identity: product, action: auth.Action("unknown.action"), wantErr: auth.ErrForbidden},
		{name: "known but ungranted health", identity: product, action: auth.ActionHealthGet, wantErr: auth.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizer.Authorize(context.Background(), tc.identity, tc.action, tc.resource)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Authorize() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestProductAllowedActionsAreKnownUniqueAndExplicit(t *testing.T) {
	seen := make(map[auth.Action]bool)
	for _, action := range ProductAllowedActions() {
		if !auth.IsKnownAction(action) {
			t.Errorf("product action %q is not registered", action)
		}
		if seen[action] {
			t.Errorf("duplicate product action %q", action)
		}
		seen[action] = true
	}
	if seen[auth.ActionHealthGet] {
		t.Fatal("health.get must remain known but ungranted")
	}
}

func TestProductAllowedActionsReturnsDefensiveSlice(t *testing.T) {
	actions := ProductAllowedActions()
	actions[0] = auth.ActionHealthGet

	authorizer := NewProductSingleAuthorizer()
	err := authorizer.Authorize(context.Background(), NewProductPrincipalIdentity("test"), auth.ActionHealthGet, auth.Resource{})
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("Authorize(health.get) error = %v, want forbidden", err)
	}
}

func TestRetiredSentrySyncActionIsUnknownAndNotAllowed(t *testing.T) {
	retired := auth.Action("sentries.sync")
	if auth.IsKnownAction(retired) {
		t.Fatal("retired sentries.sync action remains known")
	}
	for _, action := range ProductAllowedActions() {
		if action == retired {
			t.Fatal("retired sentries.sync action remains product-allowed")
		}
	}
}

func TestProductAllowedActionsCoverAuthenticatedHandlerActions(t *testing.T) {
	allowed := make(map[auth.Action]bool)
	for _, action := range ProductAllowedActions() {
		allowed[action] = true
	}
	handlerActions := []auth.Action{
		auth.ActionGenerationsView,
		auth.ActionIdentityBackup,
		auth.ActionIdentityLock,
		auth.ActionIdentityPassphrase,
		auth.ActionIdentityRestore,
		auth.ActionIdentityUnlock,
		auth.ActionIdentityView,
		auth.ActionKeyTypesActivate,
		auth.ActionKeyTypesDeactivate,
		auth.ActionKeyTypesView,
		auth.ActionKeysDelete,
		auth.ActionKeysExport,
		auth.ActionKeysGenerate,
		auth.ActionKeysImport,
		auth.ActionKeysView,
		auth.ActionPolicyUpdate,
		auth.ActionPolicyView,
		auth.ActionSentriesManage,
		auth.ActionSentriesView,
		auth.ActionSettingsUpdate,
		auth.ActionSettingsView,
		auth.ActionSignApprove,
		auth.ActionSignAssemble,
		auth.ActionSignComponent,
		auth.ActionSignRequest,
		auth.ActionTemplatesInstall,
		auth.ActionTemplatesRemove,
		auth.ActionTemplatesView,
		auth.ActionTokenProvision,
		auth.ActionTokenRevoke,
	}
	for _, action := range handlerActions {
		if !allowed[action] {
			t.Errorf("authenticated handler action %q is absent from ProductAllowedActions", action)
		}
	}
}
