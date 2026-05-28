// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlePlanRejectsWhenLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.lock()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/plan", []byte(`{"requests":[]}`))
	server.handlePlan(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signer is locked") {
		t.Fatalf("expected locked error, got %s", w.Body.String())
	}
}

func TestHandleKeysRejectsWhenLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.lock()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodGet, "/keys", nil)
	server.handleKeys(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signer is locked") {
		t.Fatalf("expected locked error, got %s", w.Body.String())
	}
}

func TestHandleHealthIsPublic(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	server.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "\"status\":\"healthy\"") {
		t.Fatalf("expected healthy status, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "\"signer_locked\":false") {
		t.Fatalf("expected unlocked status, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "\"ready_for_signing\":true") {
		t.Fatalf("expected ready_for_signing true, got %s", w.Body.String())
	}
}
