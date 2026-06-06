// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
)

func TestAuthorizerGrantDecisions(t *testing.T) {
	authorizer := NewAuthorizer(Config{
		Principals: []Principal{
			{ID: "alice", Type: "human"},
			{ID: "disabled", Type: "human", Disabled: true},
		},
		Groups: []Group{
			{ID: "operators", Members: []string{"alice"}},
			{ID: "disabled-group", Members: []string{"alice"}, Disabled: true},
		},
		Grants: []Grant{
			{Subject: GroupSubject("operators"), IdentityID: "default", Actions: []auth.Action{auth.ActionKeysView}},
			{Subject: GroupSubject("disabled-group"), IdentityID: "default", Actions: []auth.Action{auth.ActionKeysDelete}},
			{Subject: PrincipalSubject("alice"), IdentityID: "other", Actions: []auth.Action{auth.ActionSignRequest}, Disabled: true},
		},
	})

	tests := []struct {
		name     string
		identity *auth.Identity
		action   auth.Action
		resource auth.Resource
		wantErr  error
	}{
		{
			name:     "granted by group",
			identity: &auth.Identity{ID: "alice"},
			action:   auth.ActionKeysView,
			resource: auth.Resource{Type: "keys", IdentityID: "default"},
		},
		{
			name:     "wrong action fails closed",
			identity: &auth.Identity{ID: "alice"},
			action:   auth.ActionKeysGenerate,
			resource: auth.Resource{Type: "key", IdentityID: "default"},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "wrong identity fails closed",
			identity: &auth.Identity{ID: "alice"},
			action:   auth.ActionKeysView,
			resource: auth.Resource{Type: "keys", IdentityID: "other"},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "disabled principal fails closed",
			identity: &auth.Identity{ID: "disabled"},
			action:   auth.ActionKeysView,
			resource: auth.Resource{Type: "keys", IdentityID: "default"},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "unknown principal fails closed",
			identity: &auth.Identity{ID: "unknown"},
			action:   auth.ActionKeysView,
			resource: auth.Resource{Type: "keys", IdentityID: "default"},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "nil identity unauthorized",
			identity: nil,
			action:   auth.ActionKeysView,
			resource: auth.Resource{Type: "keys", IdentityID: "default"},
			wantErr:  auth.ErrUnauthorized,
		},
		{
			name:     "disabled grant fails closed",
			identity: &auth.Identity{ID: "alice"},
			action:   auth.ActionSignRequest,
			resource: auth.Resource{Type: "transaction", IdentityID: "other"},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "disabled group fails closed",
			identity: &auth.Identity{ID: "alice"},
			action:   auth.ActionKeysDelete,
			resource: auth.Resource{Type: "key", IdentityID: "default"},
			wantErr:  auth.ErrForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizer.Authorize(context.Background(), tt.identity, tt.action, tt.resource)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Authorize() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestProductSingleAuthorizerUsesBootstrapGrant(t *testing.T) {
	authorizer := NewProductSingleAuthorizer()

	for _, tc := range []struct {
		name     string
		identity *auth.Identity
		action   auth.Action
		resource auth.Resource
		wantErr  error
	}{
		{
			name:     "product principal allowed by explicit action",
			identity: NewProductPrincipalIdentity("ipc-passphrase"),
			action:   auth.ActionKeysGenerate,
			resource: auth.Resource{Type: "key", IdentityID: auth.DefaultIdentityID},
		},
		{
			name:     "compat identity maps to bootstrap principal",
			identity: &auth.Identity{ID: "alice", Type: "service", Method: "aplane-token"},
			action:   auth.ActionSignRequest,
			resource: auth.Resource{Type: "transaction", IdentityID: "alice"},
		},
		{
			name:     "product principal can rotate passphrase",
			identity: NewProductPrincipalIdentity("ipc-passphrase"),
			action:   auth.ActionIdentityPassphrase,
			resource: auth.Resource{Type: "identity", IdentityID: auth.DefaultIdentityID},
		},
		{
			name:     "product principal can remove templates",
			identity: NewProductPrincipalIdentity("ipc-passphrase"),
			action:   auth.ActionTemplatesRemove,
			resource: auth.Resource{Type: "template", IdentityID: auth.DefaultIdentityID},
		},
		{
			name:     "product principal can sync public attestors",
			identity: NewProductPrincipalIdentity("ipc-passphrase"),
			action:   auth.ActionAttestorsSync,
			resource: auth.Resource{Type: "attestors", IdentityID: auth.DefaultIdentityID},
		},
		{
			name:     "unknown action denied before grant matching",
			identity: NewProductPrincipalIdentity("ipc-passphrase"),
			action:   auth.Action("unknown.action"),
			resource: auth.Resource{Type: "system", IdentityID: auth.DefaultIdentityID},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "reserved ungranted health action denied",
			identity: NewProductPrincipalIdentity("ipc-passphrase"),
			action:   auth.ActionHealthGet,
			resource: auth.Resource{Type: "system", IdentityID: auth.DefaultIdentityID},
			wantErr:  auth.ErrForbidden,
		},
		{
			name:     "missing identity denied",
			identity: &auth.Identity{},
			action:   auth.ActionKeysView,
			resource: auth.Resource{Type: "keys", IdentityID: auth.DefaultIdentityID},
			wantErr:  auth.ErrUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizer.Authorize(context.Background(), tc.identity, tc.action, tc.resource)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Authorize() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthorizerRejectsUnknownActionEvenIfGrantContainsIt(t *testing.T) {
	typoAction := auth.Action("keys.veiw")
	authorizer := NewAuthorizer(Config{
		Principals: []Principal{{ID: "alice", Type: "human"}},
		Grants: []Grant{{
			Subject:    PrincipalSubject("alice"),
			IdentityID: auth.DefaultIdentityID,
			Actions:    []auth.Action{typoAction},
		}},
	})

	err := authorizer.Authorize(context.Background(), &auth.Identity{ID: "alice"}, typoAction, auth.Resource{
		Type:       "keys",
		IdentityID: auth.DefaultIdentityID,
	})
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("Authorize() error = %v, want %v", err, auth.ErrForbidden)
	}
}
