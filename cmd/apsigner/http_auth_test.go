// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

type stubAuthorizer struct {
	err error
	got struct {
		identityID        string
		contextIdentityID string
		action            auth.Action
		resource          auth.Resource
	}
	calls int
}

func (s *stubAuthorizer) Authorize(ctx context.Context, ident *auth.Identity, action auth.Action, resource auth.Resource) error {
	s.calls++
	if ident != nil {
		s.got.identityID = ident.ID
	}
	if ctxIdent := auth.IdentityFromContext(ctx); ctxIdent != nil {
		s.got.contextIdentityID = ctxIdent.ID
	}
	s.got.action = action
	s.got.resource = resource
	return s.err
}

func newAuthTestSigner(t *testing.T) (*Signer, func()) {
	t.Helper()
	server, cleanup := setupTestSigner(t)
	server.registryAuth = identity.NewRegistryAuthenticator(server.registry)
	return server, cleanup
}

func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v (body: %s)", err, w.Body.String())
	}
	return body["error"]
}

func TestAuthFailureReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "no credentials", err: auth.ErrNoCredentials, want: "missing_credentials"},
		{name: "invalid credentials", err: auth.ErrInvalidCredentials, want: "invalid_credentials"},
		{name: "other", err: context.Canceled, want: "auth_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authFailureReason(tt.err); got != tt.want {
				t.Fatalf("authFailureReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthRequiredError(t *testing.T) {
	if got := authRequiredError("aplane-token"); got != "Authorization header required" {
		t.Fatalf("authRequiredError(aplane-token) = %q", got)
	}
	if got := authRequiredError("ssh-passphrase"); got != "Authentication required" {
		t.Fatalf("authRequiredError(ssh-passphrase) = %q", got)
	}
}

func TestRequireAuthMissingCredentials(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := decodeErrorResponse(t, w); got != "Authorization header required" {
		t.Fatalf("error = %q, want Authorization header required", got)
	}
}

func TestRequireAuthInvalidCredentials(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.Header.Set("Authorization", "aplane wrong-token")
	server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := decodeErrorResponse(t, w); got != "Authorization header required" {
		t.Fatalf("error = %q, want Authorization header required", got)
	}
}

func TestRequireAuthForbidden(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	authz := &stubAuthorizer{err: auth.ErrForbidden}
	server.authorizer = authz

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.Header.Set("Authorization", "aplane test-token")
	server.requireAuth(auth.ActionKeysDelete, auth.Resource{Type: "key", ID: "ADDR"}, func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got := decodeErrorResponse(t, w); got != "Forbidden" {
		t.Fatalf("error = %q, want Forbidden", got)
	}
	if authz.got.identityID != auth.DefaultIdentityID {
		t.Fatalf("identityID = %q, want %q", authz.got.identityID, auth.DefaultIdentityID)
	}
	if authz.got.contextIdentityID != auth.DefaultIdentityID {
		t.Fatalf("context identityID = %q, want %q", authz.got.contextIdentityID, auth.DefaultIdentityID)
	}
	if authz.got.action != auth.ActionKeysDelete {
		t.Fatalf("action = %q, want %q", authz.got.action, auth.ActionKeysDelete)
	}
	if authz.got.resource.Type != "key" || authz.got.resource.ID != "ADDR" || authz.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("resource = %#v", authz.got.resource)
	}
}

func TestHTTPRouteAdminAttestorSyncUsesDedicatedAction(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	authz := &stubAuthorizer{err: auth.ErrForbidden}
	server.authorizer = authz

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/sentries/sync", nil)
	r.Header.Set("Authorization", "aplane test-token")
	buildHTTPServer(server, 0).Handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if authz.got.action != auth.ActionSentriesSync {
		t.Fatalf("action = %q, want %q", authz.got.action, auth.ActionSentriesSync)
	}
	if authz.got.resource.Type != "sentries" || authz.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("resource = %#v", authz.got.resource)
	}
}

func TestRequireAuthInjectsIdentityOnSuccess(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	authz := &stubAuthorizer{}
	server.authorizer = authz

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.Header.Set("Authorization", "aplane test-token")

	called := false
	server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, func(w http.ResponseWriter, r *http.Request) {
		called = true
		ident := auth.IdentityFromContext(r.Context())
		if ident == nil {
			t.Fatal("identity missing from context")
			return
		}
		if ident.ID != auth.DefaultIdentityID {
			t.Fatalf("identity ID = %q, want %q", ident.ID, auth.DefaultIdentityID)
		}
		w.WriteHeader(http.StatusNoContent)
	})(w, r)

	if !called {
		t.Fatal("next handler was not called")
	}
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
}

func TestRequireAuthAndIdentityFromRequestUseAuthenticatedIdentities(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	alice := registerAdditionalAdminTestIdentity(t, server, "alice")
	bob := registerAdditionalAdminTestIdentity(t, server, "bob")

	for _, tc := range []struct {
		name       string
		token      string
		identityID string
		runtime    *identity.Runtime
	}{
		{name: "alice", token: "alice-token", identityID: "alice", runtime: alice},
		{name: "bob", token: "bob-token", identityID: "bob", runtime: bob},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authz := &stubAuthorizer{}
			server.authorizer = authz

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/keys", nil)
			r.Header.Set("Authorization", "aplane "+tc.token)

			called := false
			server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, func(w http.ResponseWriter, r *http.Request) {
				called = true
				ident := auth.IdentityFromContext(r.Context())
				if ident == nil {
					t.Fatal("identity missing from context")
					return
				}
				if ident.ID != tc.identityID {
					t.Fatalf("identity ID = %q, want %q", ident.ID, tc.identityID)
				}

				ir, status, errMsg := server.identityFromRequest(r)
				if errMsg != "" {
					t.Fatalf("identityFromRequest() error = status %d msg %q", status, errMsg)
				}
				if ir != tc.runtime {
					t.Fatal("identityFromRequest() did not resolve authenticated runtime")
				}
				w.WriteHeader(http.StatusNoContent)
			})(w, r)

			if !called {
				t.Fatal("next handler was not called")
			}
			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", w.Code)
			}
			if authz.got.identityID != tc.identityID {
				t.Fatalf("authorizer identityID = %q, want %q", authz.got.identityID, tc.identityID)
			}
			if authz.got.contextIdentityID != tc.identityID {
				t.Fatalf("authorizer context identityID = %q, want %q", authz.got.contextIdentityID, tc.identityID)
			}
			if authz.got.resource.IdentityID != tc.identityID {
				t.Fatalf("authorizer resource identityID = %q, want %q", authz.got.resource.IdentityID, tc.identityID)
			}
		})
	}
}

func TestRequireAuthRejectsCrossIdentityResource(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	registerAdditionalAdminTestIdentity(t, server, "alice")
	registerAdditionalAdminTestIdentity(t, server, "bob")
	authz := &stubAuthorizer{}
	server.authorizer = authz

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.Header.Set("Authorization", "aplane alice-token")

	server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys", IdentityID: "bob"}, func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if authz.calls != 0 {
		t.Fatalf("authorizer calls = %d, want 0", authz.calls)
	}
}

func TestIdentityFromRequestRejectsMissingAndDecommissionedRuntime(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	t.Run("missing runtime", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/keys", nil)
		r = r.WithContext(auth.ContextWithIdentity(r.Context(), &auth.Identity{
			ID:     "missing",
			Type:   "service",
			Method: "aplane-token",
		}))

		ir, status, errMsg := server.identityFromRequest(r)
		if ir != nil || status != http.StatusForbidden || errMsg != "identity not available: missing" {
			t.Fatalf("identityFromRequest() = (%v, %d, %q), want missing runtime 403", ir, status, errMsg)
		}
	})

	t.Run("decommissioned runtime", func(t *testing.T) {
		alice := registerAdditionalAdminTestIdentity(t, server, "alice")
		if err := alice.Decommission(); err != nil {
			t.Fatalf("Decommission() error = %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/keys", nil)
		r = r.WithContext(auth.ContextWithIdentity(r.Context(), &auth.Identity{
			ID:     "alice",
			Type:   "service",
			Method: "aplane-token",
		}))

		ir, status, errMsg := server.identityFromRequest(r)
		if ir != nil || status != http.StatusForbidden || errMsg != "identity decommissioned: alice" {
			t.Fatalf("identityFromRequest() = (%v, %d, %q), want decommissioned runtime 403", ir, status, errMsg)
		}
	})
}
