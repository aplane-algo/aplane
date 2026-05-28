// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerMethodCompatibilitySurface(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	tests := []struct {
		name       string
		call       func(w *httptest.ResponseRecorder)
		wantStatus int
		wantBody   string
	}{
		{
			name: "sign requires POST",
			call: func(w *httptest.ResponseRecorder) {
				server.handleSign(w, requestWithIdentity(http.MethodGet, "/sign", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "plan requires POST",
			call: func(w *httptest.ResponseRecorder) {
				server.handlePlan(w, requestWithIdentity(http.MethodGet, "/plan", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "admin generate requires POST",
			call: func(w *httptest.ResponseRecorder) {
				server.handleAdminGenerate(w, requestWithIdentity(http.MethodGet, "/admin/generate", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "admin delete requires DELETE",
			call: func(w *httptest.ResponseRecorder) {
				server.handleAdminDelete(w, requestWithIdentity(http.MethodPost, "/admin/keys?address=TEST", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "status requires GET",
			call: func(w *httptest.ResponseRecorder) {
				server.handleStatus(w, requestWithIdentity(http.MethodPost, "/status", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "keys does not enforce GET today",
			call: func(w *httptest.ResponseRecorder) {
				server.handleKeys(w, requestWithIdentity(http.MethodPost, "/keys", nil))
			},
			wantStatus: http.StatusOK,
			wantBody:   "\"keys\":",
		},
		{
			name: "keytypes does not enforce GET today",
			call: func(w *httptest.ResponseRecorder) {
				server.handleKeyTypes(w, requestWithIdentity(http.MethodPost, "/keytypes", nil))
			},
			wantStatus: http.StatusOK,
			wantBody:   "\"key_types\":",
		},
		{
			name: "health is method-agnostic today",
			call: func(w *httptest.ResponseRecorder) {
				server.handleHealth(w, requestWithIdentity(http.MethodPost, "/health", nil))
			},
			wantStatus: http.StatusOK,
			wantBody:   "\"service\":\"Signer\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.call(w)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Fatalf("body %q does not contain %q", w.Body.String(), tt.wantBody)
			}
		})
	}
}
