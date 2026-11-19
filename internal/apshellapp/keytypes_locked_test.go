// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// newKeyTypesTestApp connects an App to a signer that lists the built-in
// key types only, as a locked signer does, and reports locked as given.
func newKeyTypesTestApp(t *testing.T, locked bool) *App {
	t.Helper()
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any
		switch r.URL.Path {
		case "/keytypes":
			body = signerapi.KeyTypesResponse{KeyTypes: []signerapi.KeyTypeInfo{
				{KeyType: "ed25519", Family: "ed25519"},
				{KeyType: "aplane.falcon1024.v1", PerKeyContract: true, BoundarySchema: "aplane.boundary.v1"},
			}}
		case "/status":
			body = signerapi.StatusResponse{SignerLocked: locked}
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(signer.Close)
	app := newEndpointTestApp(t, t.TempDir())
	app.eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	return app
}

// A locked signer lists only its built-in key types. A boundary file for a
// type the store enables said "the signer does not report key type"; it now
// says the signer is locked. An unlocked signer that does not list the type
// still says it does not report it.
func TestCheckBoundaryKeyTypeOnALockedSignerSaysLocked(t *testing.T) {
	err := newKeyTypesTestApp(t, true).CheckBoundaryKeyType(t.Context(), "aplane.ed25519.v1")
	if !errors.Is(err, engine.ErrSignerLockedForGeneration) || err.Error() != engine.ErrSignerLockedForGeneration.Error() {
		t.Fatalf("CheckBoundaryKeyType(locked) error = %v, want ErrSignerLockedForGeneration", err)
	}
	err = newKeyTypesTestApp(t, false).CheckBoundaryKeyType(t.Context(), "aplane.ed25519.v1")
	if err == nil || !strings.Contains(err.Error(), "does not report key type") {
		t.Fatalf("CheckBoundaryKeyType(unlocked) error = %v, want the type not reported", err)
	}
	if err := newKeyTypesTestApp(t, true).CheckBoundaryKeyType(t.Context(), "aplane.falcon1024.v1"); err != nil {
		t.Fatalf("CheckBoundaryKeyType(listed built-in, locked) error = %v", err)
	}
}

// keytypes says when its list is a locked signer's built-ins only.
func TestKeyTypesSaysALockedSignersListIsPartial(t *testing.T) {
	for _, locked := range []bool{true, false} {
		result, err := newKeyTypesTestApp(t, locked).KeyTypes(t.Context())
		if err != nil {
			t.Fatalf("KeyTypes(locked=%v) error = %v", locked, err)
		}
		if result.SignerLocked != locked || len(result.KeyTypes) != 2 {
			t.Fatalf("KeyTypes(locked=%v) = %+v", locked, result)
		}
	}
}
