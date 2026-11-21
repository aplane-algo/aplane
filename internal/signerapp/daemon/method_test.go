// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every route answers only its documented method; any other is 405.
func TestHandlersEnforceTheirMethod(t *testing.T) {
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
			name: "sign component requires POST",
			call: func(w *httptest.ResponseRecorder) {
				server.handleSignComponent(w, requestWithIdentity(http.MethodGet, "/sign/component", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "sign assemble requires POST",
			call: func(w *httptest.ResponseRecorder) {
				server.handleSignAssemble(w, requestWithIdentity(http.MethodGet, "/sign/assemble", nil))
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
			name: "rotating recover requires POST",
			call: func(w *httptest.ResponseRecorder) {
				server.handleRotatingRecover(w, requestWithIdentity(http.MethodGet, "/admin/rotating/recover", nil))
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
			name: "keys requires GET",
			call: func(w *httptest.ResponseRecorder) {
				server.handleKeys(w, requestWithIdentity(http.MethodPost, "/keys", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "keytypes requires GET",
			call: func(w *httptest.ResponseRecorder) {
				server.handleKeyTypes(w, requestWithIdentity(http.MethodPost, "/keytypes", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "health requires GET",
			call: func(w *httptest.ResponseRecorder) {
				server.handleHealth(w, httptest.NewRequest(http.MethodPost, "/health", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name: "health refuses HEAD",
			call: func(w *httptest.ResponseRecorder) {
				server.handleHealth(w, httptest.NewRequest(http.MethodHead, "/health", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
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
