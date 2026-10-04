// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

const signerHTTPWriteTimeout = serverconfig.MaxApprovalWait + 2*time.Minute

// The REST API listens on loopback, where any local process can connect
// before authenticating. Concurrent connections and header size are bounded
// so unauthenticated connections cannot grow the signer's memory, which
// mlockall keeps resident: beyond the cap, new connections wait in the
// kernel accept queue. Only an authenticated request keeps its connection
// alive (closeUnlessAuthenticated), so an unauthenticated client holds a
// slot for at most one request and its header timeout.
const (
	maxHTTPConnections    = 64
	maxHTTPHeaderBytes    = 64 << 10
	httpReadHeaderTimeout = 5 * time.Second
)

func buildHTTPServer(server *Signer, port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSign))
	mux.HandleFunc("/sign/bounded-admin", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleBoundedAdmin))
	mux.HandleFunc("/sign/component", server.requireAuth(auth.ActionSignComponent, auth.Resource{Type: "transaction"}, server.handleSignComponent))
	mux.HandleFunc("/sign/assemble", server.requireAuth(auth.ActionSignAssemble, auth.Resource{Type: "transaction"}, server.handleSignAssemble))
	mux.HandleFunc("/sign/cancel", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSignCancel))
	mux.HandleFunc("/plan", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handlePlan))
	mux.HandleFunc("/status", server.requireAuth(auth.ActionIdentityView, auth.Resource{Type: "identity"}, server.handleStatus))
	mux.HandleFunc("/keys", server.requireAuth(auth.ActionKeysView, auth.Resource{Type: "keys"}, server.handleKeys))
	mux.HandleFunc("/keytypes", server.requireAuth(auth.ActionKeyTypesView, auth.Resource{Type: "keytypes"}, server.handleKeyTypes))
	mux.HandleFunc("/admin/generate", server.requireAuth(auth.ActionKeysGenerate, auth.Resource{Type: "key"}, server.handleAdminGenerate))
	mux.HandleFunc("/admin/keys", server.requireAuth(auth.ActionKeysDelete, auth.Resource{Type: "key"}, server.handleAdminDelete))
	mux.HandleFunc("/health", server.handleHealth)

	return &http.Server{
		Addr:              httpBindAddr(port),
		Handler:           closeUnlessAuthenticated(mux),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      signerHTTPWriteTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxHTTPHeaderBytes,
	}
}

// closeUnlessAuthenticated closes the connection after every response that
// requireAuth did not authenticate: auth failures, /health, and unknown
// routes. Otherwise an unauthenticated client could hold every connection
// slot with keep-alive requests and leave authenticated clients waiting.
func closeUnlessAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		next.ServeHTTP(w, r)
	})
}

// listenHTTP opens the REST listener with at most maxHTTPConnections
// connections open at once.
func listenHTTP(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newLimitListener(ln, maxHTTPConnections), nil
}

// limitListener blocks Accept while n accepted connections are still open.
type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newLimitListener(ln net.Listener, n int) *limitListener {
	return &limitListener{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitListenerConn{Conn: conn, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitListenerConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitListenerConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
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
	logInfof("  POST   /sign/bounded-admin       - Prepare an external contract-admin partial")
	logInfof("  POST   /sign/component           - Produce guarded or bounded components")
	logInfof("  POST   /sign/assemble            - Assemble guarded or bounded groups")
	logInfof("  POST   /sign/cancel             - Cancel a pending sign approval request")
	logInfof("  POST   /plan                    - Preview group building (no signing, no approval)")
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
