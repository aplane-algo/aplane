// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
)

const signerHTTPWriteTimeout = apconfig.MaxApprovalWait + 2*time.Minute

func buildHTTPServer(server *Signer, port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSign))
	mux.HandleFunc("/sign/component", server.requireAuth(auth.ActionSignComponent, auth.Resource{Type: "transaction"}, server.handleSignComponent))
	mux.HandleFunc("/sign/assemble", server.requireAuth(auth.ActionSignAssemble, auth.Resource{Type: "transaction"}, server.handleSignAssemble))
	mux.HandleFunc("/sign/cancel", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSignCancel))
	mux.HandleFunc("/plan", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handlePlan))
	mux.HandleFunc("/simulate", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSimulate))
	mux.HandleFunc("/status", server.requireAuth(auth.ActionIdentityView, auth.Resource{Type: "identity"}, server.handleStatus))
	mux.HandleFunc("/keys", server.requireAuth(auth.ActionKeysView, auth.Resource{Type: "keys"}, server.handleKeys))
	mux.HandleFunc("/keytypes", server.requireAuth(auth.ActionKeyTypesView, auth.Resource{Type: "keytypes"}, server.handleKeyTypes))
	mux.HandleFunc("/admin/generate", server.requireAuth(auth.ActionKeysGenerate, auth.Resource{Type: "key"}, server.handleAdminGenerate))
	mux.HandleFunc("/admin/keys", server.requireAuth(auth.ActionKeysDelete, auth.Resource{Type: "key"}, server.handleAdminDelete))
	mux.HandleFunc("/health", server.handleHealth)

	return &http.Server{
		Addr:              httpBindAddr(port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      signerHTTPWriteTimeout,
		IdleTimeout:       120 * time.Second,
	}
}

func httpBindAddr(port int) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func logHTTPStartup(keyCount int, keysSnapshot map[string]string, port int) {
	logInfof("starting signer on port %d", port)
	logInfof("loaded %d key(s)", keyCount)
	i := 1
	for address := range keysSnapshot {
		logInfof("  %d. %s", i, address)
		i++
	}
	logInfof("Endpoints:")
	logInfof("  POST   /sign                    - Sign transactions (handles groups, dummies, fee pooling)")
	logInfof("  POST   /sign/component          - Produce attestor MVP component signatures")
	logInfof("  POST   /sign/assemble           - Assemble attested-account signed groups")
	logInfof("  POST   /sign/cancel             - Cancel a pending sign approval request")
	logInfof("  POST   /plan                    - Preview group building (no signing, no approval)")
	logInfof("  POST   /simulate                - Sign internally and run algod simulation (no signed bytes returned)")
	logInfof("  GET    /status                  - Signer status and keyset revision")
	logInfof("  GET    /keys                    - List all available signing addresses")
	logInfof("  GET    /keytypes                - List available key types and creation parameters")
	logInfof("  POST   /admin/generate          - Generate a new key")
	logInfof("  DELETE /admin/keys?address=...  - Delete a key (soft delete)")
	logInfof("  GET    /health                  - Health check")
	logInfof("Key Management:")
	logInfof("  Use 'apadmin' tool or /admin/* REST endpoints for key operations")
	logInfof("  Keys auto-reload when filesystem changes detected")
	logInfof(strings.Repeat("=", 50))
	logInfof("REST API listening on %s (localhost only - accessed via SSH tunnel)", httpBindAddr(port))
}
