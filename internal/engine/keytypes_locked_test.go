// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// lockedSignerForKeyTypesTest answers /keytypes with the built-in types only,
// as a locked signer does, and /status with locked.
func lockedSignerForKeyTypesTest(t *testing.T, locked bool) *Engine {
	t.Helper()
	return newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/keytypes":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeyTypesResponse{
				KeyTypes: []signerapi.KeyTypeInfo{{KeyType: "ed25519", Family: "ed25519"}},
			}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/status":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.StatusResponse{SignerLocked: locked}, req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})
}

// A locked signer lists only its built-in key types, so generating a type
// the store enables said "unknown key type". It now says the signer is
// locked; an unlocked signer that does not list the type still says unknown.
func TestGenerateKeyOfAnUnlistedTypeOnALockedSignerSaysLocked(t *testing.T) {
	params := map[string]string{"rekey_to": "ADDR"}
	_, err := lockedSignerForKeyTypesTest(t, true).GenerateKey(context.Background(), "aplane.ed25519.v1", params)
	if !errors.Is(err, ErrSignerLockedForGeneration) {
		t.Fatalf("GenerateKey(locked) error = %v, want ErrSignerLockedForGeneration", err)
	}

	_, err = lockedSignerForKeyTypesTest(t, false).GenerateKey(context.Background(), "aplane.ed25519.v1", params)
	if err == nil || !strings.Contains(err.Error(), "unknown key type: aplane.ed25519.v1") {
		t.Fatalf("GenerateKey(unlocked) error = %v, want unknown key type", err)
	}
}

// KeyTypesForGeneration answers a listed type from the listing without
// asking for the lock state.
func TestKeyTypesForGenerationListedTypeNeedsNoStatus(t *testing.T) {
	eng := newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/keytypes" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeyTypesResponse{
			KeyTypes: []signerapi.KeyTypeInfo{{KeyType: "ed25519", Family: "ed25519"}},
		}, req), nil
	})
	got, err := eng.KeyTypesForGeneration(context.Background(), "ed25519")
	if err != nil || len(got) != 1 {
		t.Fatalf("KeyTypesForGeneration() = %v, %v", got, err)
	}
}
