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
	product := auth.NewProductIdentity("ipc-passphrase")

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
	err := authorizer.Authorize(context.Background(), auth.NewProductIdentity("test"), auth.ActionHealthGet, auth.Resource{})
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("Authorize(health.get) error = %v, want forbidden", err)
	}
}

func TestRetiredCosignerSyncActionIsUnknownAndNotAllowed(t *testing.T) {
	retired := auth.Action("cosigners.sync")
	if auth.IsKnownAction(retired) {
		t.Fatal("retired cosigners.sync action remains known")
	}
	for _, action := range ProductAllowedActions() {
		if action == retired {
			t.Fatal("retired cosigners.sync action remains product-allowed")
		}
	}
}

func TestProductAllowedActionsCoverAuthenticatedHandlerActions(t *testing.T) {
	allowed := make(map[auth.Action]bool)
	for _, action := range ProductAllowedActions() {
		allowed[action] = true
	}
	handlerActions := []auth.Action{
		auth.ActionGenerationQuarantinePrune,
		auth.ActionGenerationAbandonedDiscard,
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
		auth.ActionCosignersManage,
		auth.ActionCosignersView,
		auth.ActionSettingsUpdate,
		auth.ActionSettingsView,
		auth.ActionSignApprove,
		auth.ActionSignAssemble,
		auth.ActionSignComponent,
		auth.ActionSignRequest,
		auth.ActionTemplatesInstall,
		auth.ActionTemplatesRemove,
		auth.ActionTemplatesView,
		auth.ActionClientsView,
		auth.ActionClientsEnroll,
		auth.ActionClientsRevoke,
	}
	for _, action := range handlerActions {
		if !allowed[action] {
			t.Errorf("authenticated handler action %q is absent from ProductAllowedActions", action)
		}
	}
}

// A client principal is authorized by its role table, never by the product
// admin set, and an empty or unknown role is denied.
func TestClientRoleActions(t *testing.T) {
	a := NewProductSingleAuthorizer()
	client := auth.NewClientIdentity("SHA256:abc", "laptop")
	for _, action := range ClientAllowedActions() {
		if err := a.Authorize(context.Background(), client, action, auth.Resource{}); err != nil {
			t.Errorf("client denied %q: %v", action, err)
		}
	}
	for _, action := range []auth.Action{auth.ActionPolicyUpdate, auth.ActionClientsRevoke, auth.ActionIdentityUnlock, auth.ActionKeysImport, auth.ActionClientsView} {
		if err := a.Authorize(context.Background(), client, action, auth.Resource{}); !errors.Is(err, auth.ErrForbidden) {
			t.Errorf("client allowed %q: %v", action, err)
		}
	}
	noRole := &auth.Identity{ID: auth.ClientPrincipalPrefix + "SHA256:abc", Type: "client"}
	if err := a.Authorize(context.Background(), noRole, auth.ActionKeysView, auth.Resource{}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("client without a role allowed: %v", err)
	}
	unknownRole := auth.NewClientIdentity("SHA256:abc", "")
	unknownRole.Role = "admin"
	if err := a.Authorize(context.Background(), unknownRole, auth.ActionKeysView, auth.Resource{}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("client with an unknown role allowed: %v", err)
	}
	if err := a.Authorize(context.Background(), &auth.Identity{ID: "other:thing", Role: auth.RoleClient}, auth.ActionKeysView, auth.Resource{}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("non-client principal with a client role allowed: %v", err)
	}
}

func TestClientAllowedActionsAreKnownAndNeverAdministrative(t *testing.T) {
	for _, action := range ClientAllowedActions() {
		if !auth.IsKnownAction(action) {
			t.Errorf("client action %q is unknown", action)
		}
		switch action {
		case auth.ActionIdentityUnlock, auth.ActionIdentityPassphrase, auth.ActionKeysImport, auth.ActionKeysExport,
			auth.ActionPolicyUpdate, auth.ActionSettingsUpdate, auth.ActionClientsEnroll, auth.ActionClientsRevoke, auth.ActionClientsView:
			t.Errorf("client action set grants administrative action %q", action)
		}
	}
}
