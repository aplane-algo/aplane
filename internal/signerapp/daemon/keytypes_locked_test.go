// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /keytypes needs no unlock, but a locked signer answered it, and the admin
// ListKeyTypes, with "failed to read key type activations". Both list the
// built-in key types instead.
func TestKeyTypesAnswerWhileLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	server.productRuntime().Lock()

	w := httptest.NewRecorder()
	server.handleKeyTypes(w, requestWithIdentity(http.MethodGet, "/keytypes", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/keytypes while locked = %d: %s", w.Code, w.Body.String())
	}
	keyTypes := fetchKeyTypesForTest(t, server)
	if _, ok := findKeyTypeInfo(keyTypes, "ed25519"); !ok {
		t.Fatalf("/keytypes while locked lacks the built-in ed25519: %+v", keyTypes)
	}

	result := server.adminServices().templateServices().ListKeyTypes()
	if result.Error != "" {
		t.Fatalf("ListKeyTypes while locked: %s (%s)", result.Error, result.Code)
	}
	if len(result.KeyTypes) != len(keyTypes) {
		t.Fatalf("ListKeyTypes while locked = %d key types, /keytypes = %d", len(result.KeyTypes), len(keyTypes))
	}
}
