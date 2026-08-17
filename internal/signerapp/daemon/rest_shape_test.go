// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/version"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestReadEndpointJSONShapes(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	tests := []struct {
		name       string
		invoke     func(w *httptest.ResponseRecorder)
		wantStatus int
		want       map[string]any
	}{
		{
			name: "health",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
			},
			wantStatus: http.StatusOK,
			want: map[string]any{
				"status":            "healthy",
				"service":           "Signer",
				"protocol_version":  map[string]any{"major": float64(2), "minor": float64(0)},
				"build_version":     version.String(),
				"signer_locked":     false,
				"ready_for_signing": true,
				"ssh_enabled":       false,
				"ipc_enabled":       false,
			},
		},
		{
			name: "status",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleStatus(w, requestWithIdentity(http.MethodGet, "/status", nil))
			},
			wantStatus: http.StatusOK,
			want: map[string]any{
				"identity_id":           "default",
				"node_role":             "signer",
				"protocol_version":      map[string]any{"major": float64(2), "minor": float64(0)},
				"build_version":         version.String(),
				"state":                 "unlocked",
				"signer_locked":         false,
				"ready_for_signing":     true,
				"key_count":             float64(0),
				"keyset_revision":       float64(0),
				"approval_wait_seconds": float64(60),
			},
		},
		{
			name: "keys_empty",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleKeys(w, requestWithIdentity(http.MethodGet, "/keys", nil))
			},
			wantStatus: http.StatusOK,
			want: map[string]any{
				"count": float64(0),
				"keys":  []any{},
			},
		},
		{
			name: "keytypes_top_level",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleKeyTypes(w, requestWithIdentity(http.MethodGet, "/keytypes", nil))
			},
			wantStatus: http.StatusOK,
			want: map[string]any{
				"key_types": func() []any { return []any{} }(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.invoke(w)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.wantStatus, w.Body.String())
			}

			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if tt.name == "keytypes_top_level" {
				value, ok := got["key_types"]
				if !ok {
					t.Fatalf("response missing key_types: %#v", got)
				}
				if _, ok := value.([]any); !ok {
					t.Fatalf("key_types has wrong type %T", value)
				}
				if len(got) != 1 {
					t.Fatalf("unexpected top-level fields: %#v", got)
				}
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("JSON shape mismatch\n got: %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}

func TestErrorEnvelopeJSONShapes(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	tests := []struct {
		name       string
		invoke     func(w *httptest.ResponseRecorder)
		wantStatus int
		want       map[string]any
	}{
		{
			name: "sign_method_not_allowed",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleSign(w, requestWithIdentity(http.MethodGet, "/sign", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			want: map[string]any{
				"error": "Method not allowed",
				"code":  "bad_request",
			},
		},
		{
			name: "plan_method_not_allowed",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handlePlan(w, requestWithIdentity(http.MethodGet, "/plan", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			want: map[string]any{
				"error": "Method not allowed",
				"code":  "bad_request",
			},
		},
		{
			name: "sign_component_method_not_allowed",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleSignComponent(w, requestWithIdentity(http.MethodGet, "/sign/component", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			want: map[string]any{
				"error": "Method not allowed",
				"code":  "bad_request",
			},
		},
		{
			name: "sign_assemble_method_not_allowed",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleSignAssemble(w, requestWithIdentity(http.MethodGet, "/sign/assemble", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			want: map[string]any{
				"error": "Method not allowed",
				"code":  "bad_request",
			},
		},
		{
			name: "admin_generate_method_not_allowed",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleAdminGenerate(w, requestWithIdentity(http.MethodGet, "/admin/generate", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			want: map[string]any{
				"error": "Method not allowed",
				"code":  "bad_request",
			},
		},
		{
			name: "admin_delete_method_not_allowed",
			invoke: func(w *httptest.ResponseRecorder) {
				server.handleAdminDelete(w, requestWithIdentity(http.MethodPost, "/admin/keys?address=TEST", nil))
			},
			wantStatus: http.StatusMethodNotAllowed,
			want: map[string]any{
				"error": "Method not allowed",
				"code":  "bad_request",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.invoke(w)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.wantStatus, w.Body.String())
			}

			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("JSON shape mismatch\n got: %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}
