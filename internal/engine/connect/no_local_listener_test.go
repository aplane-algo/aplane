// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/sshtunnel/sshtest"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A connection to a signer opens no port on this machine: every request
// travels over an SSH channel opened in-process, so no other local process
// can borrow the client's enrolled identity.
func TestConnectOpensNoLocalListener(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("counts this process's listening sockets through /proc")
	}
	var requests atomic.Int32
	node := sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/keys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A"}}})
	}))
	before := listeningSockets(t)

	state := NewState()
	result, err := state.ConnectWithTunnel(context.Background(), "node", node.Host, node.Port, node.IdentityFile, node.KnownHostsPath, nil, nil, nil)
	if err != nil {
		t.Fatalf("ConnectWithTunnel() error = %v", err)
	}
	t.Cleanup(func() { state.Disconnect(nil) })
	if result.KeyCount != 1 || requests.Load() != 1 {
		t.Fatalf("result = %+v after %d request(s), want a connection that read one key", result, requests.Load())
	}
	if _, err := state.SignerClient.GetKeysWithContext(context.Background()); err != nil || requests.Load() != 2 {
		t.Fatalf("a later request failed (%v) or did not reach the node (%d requests)", err, requests.Load())
	}
	for inode := range listeningSockets(t) {
		if !before[inode] {
			t.Fatalf("connecting opened a listening socket (inode %s)", inode)
		}
	}
}

// listeningSockets returns the inodes of the TCP sockets this process holds
// in the LISTEN state.
func listeningSockets(t *testing.T) map[string]bool {
	t.Helper()
	owned := map[string]bool{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	listening := map[string]bool{}
	for _, table := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		f, err := os.Open(table)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// sl local remote st tx:rx tr:when retrnsmt uid timeout inode
			fields := strings.Fields(scanner.Text())
			if len(fields) > 9 && fields[3] == "0A" && owned[fields[9]] {
				listening[fields[9]] = true
			}
		}
		_ = f.Close()
	}
	return listening
}

// The context a connect runs under bounds its setup only: the command that
// connected ends, and with it its context, while the connection stays.
func TestConnectionOutlivesTheContextItWasMadeUnder(t *testing.T) {
	node := sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A"}}})
	}))
	state := NewState()
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := state.ConnectWithTunnel(ctx, "node", node.Host, node.Port, node.IdentityFile, node.KnownHostsPath, nil, nil, nil); err != nil {
		t.Fatalf("ConnectWithTunnel() error = %v", err)
	}
	t.Cleanup(func() { state.Disconnect(nil) })
	cancel()
	if _, err := state.SignerClient.GetKeysWithContext(context.Background()); err != nil {
		t.Fatalf("a request after the connecting context ended failed: %v", err)
	}
}

// A connect whose context ends during setup fails and keeps nothing.
func TestConnectEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	node := sshtest.Serve(t, http.NotFoundHandler())
	state := NewState()
	if _, err := state.ConnectWithTunnel(ctx, "node", node.Host, node.Port, node.IdentityFile, node.KnownHostsPath, nil, nil, nil); err == nil {
		t.Fatal("ConnectWithTunnel() under an ended context connected")
	}
	if state.SignerClient != nil || state.SSHTunnelClient != nil {
		t.Fatal("the cancelled connect left a connection behind")
	}
}

// A connect refused because the enrolled key is already at the server's
// per-key connection limit reports the limit rather than a raw EOF.
func TestConnectReportsConnectionLimitReached(t *testing.T) {
	node := sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A"}}})
	}))

	// Fill all 8 per-key authenticated slots with the enrolled client key.
	for i := 0; i < 8; i++ {
		st := NewState()
		if _, err := st.ConnectWithTunnel(context.Background(), "node", node.Host, node.Port, node.IdentityFile, node.KnownHostsPath, nil, nil, nil); err != nil {
			t.Fatalf("ConnectWithTunnel(%d) error = %v", i+1, err)
		}
		t.Cleanup(func() { st.Disconnect(nil) })
	}

	overflow := NewState()
	_, err := overflow.ConnectWithTunnel(context.Background(), "node", node.Host, node.Port, node.IdentityFile, node.KnownHostsPath, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "signer connection limit reached") {
		t.Fatalf("9th ConnectWithTunnel() error = %v, want signer connection limit reached", err)
	}
}
