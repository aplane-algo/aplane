// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// The known_hosts entry names the host as ssh would: bare on port 22,
// bracketed with the port otherwise. Blank lines and other entries already in
// the file are kept, and an entry already present is not written again.
func TestTrustLocalSignerHostKeyAddressForms(t *testing.T) {
	tests := []struct {
		url     string
		address string
	}{
		{"ssh://localhost", "[localhost]:1127"},
		{"ssh://localhost:22", "localhost"},
		{"ssh://127.0.0.1:56870", "[127.0.0.1]:56870"},
		{"ssh://[::1]:2222", "[::1]:2222"},
		{"ssh://[::1]:22", "::1"},
		{"ssh://[::ffff:127.0.0.1]:2200", "[::ffff:127.0.0.1]:2200"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			clientDir := t.TempDir()
			hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
			hostKey := loadTestSSHPublicKey(t, hostKeyPath)
			stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
			if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte("network: testnet\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeClientEndpointRegistry(t, clientDir, `
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: `+tt.url+`
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
`)
			knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
			if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
				t.Fatal(err)
			}
			existing := "\n\nother.example.com ssh-ed25519 AAAA\n\n"
			if err := os.WriteFile(knownHostsPath, []byte(existing), 0o600); err != nil {
				t.Fatal(err)
			}

			notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
			if err != nil {
				t.Fatal(err)
			}
			if want := "trusted local signer SSH host key for " + tt.address; notice != want {
				t.Fatalf("notice = %q, want %q", notice, want)
			}
			line := knownhosts.Line([]string{tt.address}, hostKey)
			data, err := os.ReadFile(knownHostsPath)
			if err != nil {
				t.Fatal(err)
			}
			if want := existing + line + "\n"; string(data) != want {
				t.Fatalf("known_hosts = %q, want %q", data, want)
			}

			notice, err = trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
			if err != nil || notice != "" {
				t.Fatalf("second trust = %q, %v; want nothing written", notice, err)
			}
			if again, _ := os.ReadFile(knownHostsPath); string(again) != string(data) {
				t.Fatalf("known_hosts changed on the second trust: %q", again)
			}
		})
	}
}
