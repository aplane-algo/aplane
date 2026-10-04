// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
