// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	authzpkg "github.com/aplane-algo/aplane/internal/authz"
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
	if authz.got.identityID != authzpkg.SystemProductAdminPrincipalID {
		t.Fatalf("identityID = %q, want %q", authz.got.identityID, authzpkg.SystemProductAdminPrincipalID)
	}
	if authz.got.contextIdentityID != authzpkg.SystemProductAdminPrincipalID {
		t.Fatalf("context identityID = %q, want %q", authz.got.contextIdentityID, authzpkg.SystemProductAdminPrincipalID)
	}
	if authz.got.action != auth.ActionKeysDelete {
		t.Fatalf("action = %q, want %q", authz.got.action, auth.ActionKeysDelete)
	}
	if authz.got.resource.Type != "key" || authz.got.resource.ID != "ADDR" {
		t.Fatalf("resource = %#v", authz.got.resource)
	}
}

func TestHTTPRouteAdminSentrySyncIsNotRegistered(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	authz := &stubAuthorizer{}
	server.authorizer = authz

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/sentries/sync", nil)
	r.Header.Set("Authorization", "aplane test-token")
	buildHTTPServer(server, 0).Handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if authz.got.action != "" {
		t.Fatalf("retired route reached authorization with action %q", authz.got.action)
	}
}

func TestRequireAuthInjectsIdentityOnSuccess(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	authorizer := &stubAuthorizer{}
	server.authorizer = authorizer

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
		if ident.ID != authzpkg.SystemProductAdminPrincipalID {
			t.Fatalf("principal ID = %q, want %q", ident.ID, authzpkg.SystemProductAdminPrincipalID)
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

func TestRequireAuthBindsProductPrincipalAndRuntime(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	productRuntime := server.productIdentityRuntime()

	invalid := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodGet, "/keys", nil)
	invalidRequest.Header.Set("Authorization", "aplane non-product-token")
	server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, func(http.ResponseWriter, *http.Request) {
		t.Fatal("additional runtime token must not authenticate")
	})(invalid, invalidRequest)
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("additional runtime token status = %d, want 401", invalid.Code)
	}

	authorizer := &stubAuthorizer{}
	server.authorizer = authorizer
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.Header.Set("Authorization", "aplane test-token")
	server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, func(w http.ResponseWriter, r *http.Request) {
		ident := auth.IdentityFromContext(r.Context())
		if ident == nil || ident.ID != authzpkg.SystemProductAdminPrincipalID {
			t.Fatalf("authenticated principal = %#v", ident)
		}
		ir, status, errMsg := server.identityFromRequest(r)
		if errMsg != "" || status != 0 || ir != productRuntime {
			t.Fatalf("identityFromRequest() = (%v, %d, %q), want product runtime", ir, status, errMsg)
		}
		w.WriteHeader(http.StatusNoContent)
	})(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if authorizer.got.identityID != authzpkg.SystemProductAdminPrincipalID {
		t.Fatalf("authorization binding = %#v", authorizer.got)
	}
}

func TestIdentityFromRequestIgnoresPrincipalIDAndPreservesNodeFailClosed(t *testing.T) {
	server, cleanup := newAuthTestSigner(t)
	defer cleanup()

	t.Run("principal does not select runtime", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/keys", nil)
		r = r.WithContext(auth.ContextWithIdentity(r.Context(), &auth.Identity{
			ID:     "missing",
			Type:   "system",
			Method: "aplane-token",
		}))

		ir, status, errMsg := server.identityFromRequest(r)
		if ir != server.productIdentityRuntime() || status != 0 || errMsg != "" {
			t.Fatalf("identityFromRequest() = (%v, %d, %q), want fixed product runtime", ir, status, errMsg)
		}
	})

	t.Run("node fail closed", func(t *testing.T) {
		server.nodeFailState.Fail(context.Canceled)
		r := httptest.NewRequest(http.MethodGet, "/keys", nil)
		ir, status, errMsg := server.identityFromRequest(r)
		if ir != nil || status != http.StatusServiceUnavailable || errMsg == "" {
			t.Fatalf("identityFromRequest() = (%v, %d, %q), want node-fail-closed 503", ir, status, errMsg)
		}
	})
}
