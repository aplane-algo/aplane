// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeEndpointIdentity(t *testing.T, dataDir, passphrase string) ssh.PublicKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(privateKey, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(dataDir, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sshKey
}

func endpointForPublicKey(t *testing.T, dataDir string) *App {
	t.Helper()
	app := newEndpointTestApp(t, dataDir)
	if _, err := app.EndpointCreateCosigner(t.Context(), EndpointCreateCosignerRequest{
		Alias: "cosigner-local", URL: "ssh://127.0.0.1:2223",
	}); err != nil {
		t.Fatal(err)
	}
	return app
}

func TestEndpointPublicKeyIsRepeatableAcrossRestarts(t *testing.T) {
	dataDir := t.TempDir()
	want := writeEndpointIdentity(t, dataDir, "")

	first, err := endpointForPublicKey(t, dataDir).EndpointPublicKey(t.Context(), "cosigner-local")
	if err != nil {
		t.Fatalf("EndpointPublicKey() error = %v", err)
	}
	second, err := newEndpointTestApp(t, dataDir).EndpointPublicKey(t.Context(), "cosigner-local")
	if err != nil {
		t.Fatalf("EndpointPublicKey() after restart error = %v", err)
	}

	if *first != *second {
		t.Fatalf("read %+v then %+v", first, second)
	}
	if first.Fingerprint != ssh.FingerprintSHA256(want) || first.Alias != "cosigner-local" {
		t.Fatalf("result = %+v", first)
	}
	if !strings.HasPrefix(first.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("PublicKey = %q", first.PublicKey)
	}
}

func TestEndpointPublicKeyNeverCreatesAKey(t *testing.T) {
	dataDir := t.TempDir()
	app := endpointForPublicKey(t, dataDir)

	_, err := app.EndpointPublicKey(t.Context(), "cosigner-local")

	if err == nil || !strings.Contains(err.Error(), "created the first time it connects") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, ".ssh", "id_ed25519")); !os.IsNotExist(statErr) {
		t.Fatalf("a key appeared: %v", statErr)
	}
}

func TestEndpointPublicKeyExplainsAnEncryptedKey(t *testing.T) {
	dataDir := t.TempDir()
	writeEndpointIdentity(t, dataDir, "passphrase")
	app := endpointForPublicKey(t, dataDir)

	_, err := app.EndpointPublicKey(t.Context(), "cosigner-local")

	if err == nil || !strings.Contains(err.Error(), "ssh-keygen -y -f ") {
		t.Fatalf("error = %v, want the way to read it", err)
	}
	if strings.Contains(err.Error(), "ssh-add") {
		t.Fatalf("error = %v; an agent only lists keys already loaded", err)
	}
}

func TestEndpointPublicKeyNeedsAKnownEndpoint(t *testing.T) {
	app := endpointForPublicKey(t, t.TempDir())
	if _, err := app.EndpointPublicKey(t.Context(), "missing"); err == nil || !strings.Contains(err.Error(), "unknown endpoint") {
		t.Fatalf("error = %v", err)
	}
}

func TestEndpointPublicKeyWithoutAliasNeedsADefault(t *testing.T) {
	app := endpointForPublicKey(t, t.TempDir())
	_, err := app.EndpointPublicKey(t.Context(), "")
	if err == nil || !strings.Contains(err.Error(), "no default endpoint") {
		t.Fatalf("error = %v", err)
	}
}
