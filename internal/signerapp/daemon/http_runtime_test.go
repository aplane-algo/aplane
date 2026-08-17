// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aplane-algo/aplane/internal/serverconfig"
)

func TestHTTPWriteTimeoutCoversApprovalWait(t *testing.T) {
	server := buildHTTPServer(nil, 0)
	if server.WriteTimeout <= serverconfig.DefaultApprovalWait {
		t.Fatalf("WriteTimeout = %s, want greater than default approval wait %s", server.WriteTimeout, serverconfig.DefaultApprovalWait)
	}
	if server.WriteTimeout <= serverconfig.MaxApprovalWait {
		t.Fatalf("WriteTimeout = %s, want greater than max approval wait %s", server.WriteTimeout, serverconfig.MaxApprovalWait)
	}
}

func TestHTTPServerDoesNotExposeSignerSimulationRoutes(t *testing.T) {
	handler := buildHTTPServer(nil, 0).Handler
	for _, path := range []string{
		"/simulate", "/simulate/guarded",
		"/sign/bounded-component", "/sign/bounded-assemble",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("POST %s status = %d, want %d", path, w.Code, http.StatusNotFound)
			}
		})
	}
}
