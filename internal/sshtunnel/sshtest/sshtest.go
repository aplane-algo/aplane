// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sshtest fronts an http.Handler with an in-process aplane SSH
// server, the way a client reaches a signer or cosigner node: the client
// authenticates with its enrolled key over SSH, and its API channels are
// handed to the handler with that identity attached. Tests use it in place
// of a loopback HTTP server, because a node is reachable only this way.
package sshtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// Node is a running in-process node front.
type Node struct {
	// URL is the ssh:// endpoint URL clients configure.
	URL string
	// Host and Port split URL.
	Host string
	Port int
	// IdentityFile is the client private key the node was started with, and
	// KnownHostsPath pins the node's host key for it.
	IdentityFile   string
	KnownHostsPath string
	// Fingerprint is the SHA256 fingerprint of the client key in IdentityFile.
	Fingerprint string
	// Server is the SSH server, for tests that need to close connections.
	Server *sshtunnel.Server

	mu       sync.Mutex
	enrolled map[string]bool
	approve  func(fingerprint, label string) bool
	requests []EnrollmentRequest
}

// EnrollmentRequest is one request-enrollment the node received.
type EnrollmentRequest struct {
	Fingerprint string
	Label       string
	Approved    bool
}

// Options adjust how the node starts.
type Options struct {
	// Unenrolled starts the node without the client key enrolled, so the
	// first connection is refused until the client enrolls.
	Unenrolled bool
	// Approve decides enrollment requests; nil approves every request.
	Approve func(fingerprint, label string) bool
	// Dir holds the client identity (id_ed25519), known_hosts, and host key;
	// a temp dir when empty. Pointing it at a client data directory's .ssh
	// makes the node reachable through that client's default identity.
	Dir string
}

// Serve starts a node fronting handler with the client key enrolled.
func Serve(t testing.TB, handler http.Handler) *Node {
	return ServeWithOptions(t, handler, Options{})
}

// ServeWithOptions starts a node fronting handler.
func ServeWithOptions(t testing.TB, handler http.Handler, opts Options) *Node {
	t.Helper()
	dir := opts.Dir
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("sshtest: create %s: %v", dir, err)
	}
	identityFile, clientPub := writeClientIdentity(t, dir)
	node := &Node{
		IdentityFile: identityFile,
		Fingerprint:  ssh.FingerprintSHA256(clientPub),
		enrolled:     make(map[string]bool),
		approve:      opts.Approve,
	}
	if !opts.Unenrolled {
		node.enrolled[node.Fingerprint] = true
	}

	server, err := sshtunnel.NewServer("127.0.0.1:0", filepath.Join(dir, "ssh_host_key"))
	if err != nil {
		t.Fatalf("sshtest: NewServer: %v", err)
	}
	node.Server = server
	server.SetProductHooks(sshtunnel.ProductHooks{
		CheckKey: func(key ssh.PublicKey) bool {
			node.mu.Lock()
			defer node.mu.Unlock()
			return node.enrolled[ssh.FingerprintSHA256(key)]
		},
		EnrollKey: func(key ssh.PublicKey, _ string) (bool, error) {
			node.mu.Lock()
			defer node.mu.Unlock()
			fp := ssh.FingerprintSHA256(key)
			added := !node.enrolled[fp]
			node.enrolled[fp] = true
			return added, nil
		},
	})
	server.SetEnrollmentHooks(sshtunnel.EnrollmentHooks{
		ApproveContext: func(_ context.Context, fingerprint, label, _ string) (bool, error) {
			approved := node.approve == nil || node.approve(fingerprint, label)
			node.mu.Lock()
			node.requests = append(node.requests, EnrollmentRequest{Fingerprint: fingerprint, Label: label, Approved: approved})
			node.mu.Unlock()
			return approved, nil
		},
		AuditEnrolled:     func(string, string, string) {},
		OperatorConnected: func() bool { return true },
	})

	listener := sshtunnel.NewAPIListener(64)
	server.SetAPIHandoff(listener.Handoff)
	httpServer := &http.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if api, ok := c.(*sshtunnel.APIConn); ok {
				return auth.ContextWithConnIdentity(ctx, auth.ConnIdentity{KeyFingerprint: api.KeyFingerprint()})
			}
			return ctx
		},
	}
	go func() { _ = httpServer.Serve(listener) }()

	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("sshtest: Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = server.Stop()
		_ = listener.Close()
		_ = httpServer.Close()
	})

	host, portText, err := net.SplitHostPort(server.ListenAddr())
	if err != nil {
		t.Fatalf("sshtest: listener address: %v", err)
	}
	port, _ := strconv.Atoi(portText)
	node.Host, node.Port = host, port
	node.URL = fmt.Sprintf("ssh://%s:%d", host, port)
	node.KnownHostsPath = filepath.Join(dir, "known_hosts")
	line := knownhosts.Line([]string{fmt.Sprintf("[%s]:%d", host, port)}, server.HostPublicKey()) + "\n"
	if err := os.WriteFile(node.KnownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatalf("sshtest: write known_hosts: %v", err)
	}
	return node
}

// Enrolled reports whether the key with fingerprint is enrolled.
func (n *Node) Enrolled(fingerprint string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.enrolled[fingerprint]
}

// Revoke removes the key from the registry and closes its connections.
func (n *Node) Revoke(fingerprint string) int {
	n.mu.Lock()
	delete(n.enrolled, fingerprint)
	n.mu.Unlock()
	return n.Server.CloseConnectionsForFingerprint(fingerprint, "key revoked")
}

// EnrollmentRequests returns the enrollment requests received so far.
func (n *Node) EnrollmentRequests() []EnrollmentRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]EnrollmentRequest(nil), n.requests...)
}

func writeClientIdentity(t testing.TB, dir string) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sshtest: generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("sshtest: signer: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("sshtest: marshal client key: %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("sshtest: write client key: %v", err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		t.Fatalf("sshtest: write client public key: %v", err)
	}
	return path, signer.PublicKey()
}
