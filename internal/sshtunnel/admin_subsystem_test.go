// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestAdminSubsystemCarriesBytes(t *testing.T) {
	srv, tmpDir := testServer(t)

	_, clientPub, identityPath := generateClientIdentityFile(t, tmpDir)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, clientPub)
	srv.authKeysMu.Unlock()

	srv.SetAdminChannelCallback(func(channel ssh.Channel, remoteAddr, identityID string) {
		defer func() { _ = channel.Close() }()
		reader := bufio.NewReader(channel)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = channel.Write([]byte(strings.ToUpper(line)))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Stop() }()

	host, port := splitHostPort(t, srv.listener.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey())+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile(known_hosts) error = %v", err)
	}

	client := NewClient(host, port, 0, 0, identityPath, knownHostsPath)
	client.SetAPIToken("test-token")
	if err := client.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("ConnectWithKey() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.OpenSubsystem(AdminSubsystemName)
	if err != nil {
		t.Fatalf("OpenSubsystem() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	if _, err := stream.Write([]byte("hello subsystem\n")); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}

	reply := make([]byte, len("HELLO SUBSYSTEM\n"))
	if _, err := stream.Read(reply); err != nil {
		t.Fatalf("stream.Read() error = %v", err)
	}
	if got := string(reply); got != "HELLO SUBSYSTEM\n" {
		t.Fatalf("reply = %q, want %q", got, "HELLO SUBSYSTEM\n")
	}
}

func generateClientIdentityFile(t *testing.T, dir string) (ssh.Signer, ssh.PublicKey, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}

	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("WriteFile(identity) error = %v", err)
	}

	return signer, signer.PublicKey(), path
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Sscanf(%q) error = %v", addr, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("Sscanf(%q) error = %v", portStr, err)
	}
	return host, port
}

func hostWithPort(host string, port int) string {
	return fmt.Sprintf("[%s]:%d", host, port)
}
