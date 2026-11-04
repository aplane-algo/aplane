// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeIdentity(t *testing.T, passphrase string) (path string, want ssh.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(privateKey, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	want, err = ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	return path, want
}

func TestReadIdentityPublicKeyDerivesTheExistingKey(t *testing.T) {
	path, want := writeIdentity(t, "")

	got, err := ReadIdentityPublicKey(path)
	if err != nil {
		t.Fatalf("ReadIdentityPublicKey() error = %v", err)
	}

	if got.Fingerprint != ssh.FingerprintSHA256(want) {
		t.Fatalf("Fingerprint = %q, want %q", got.Fingerprint, ssh.FingerprintSHA256(want))
	}
	parsed, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(got.AuthorizedKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(%q) error = %v", got.AuthorizedKey, err)
	}
	if len(rest) != 0 || !bytes.Equal(parsed.Marshal(), want.Marshal()) {
		t.Fatalf("AuthorizedKey = %q, want the file's own key", got.AuthorizedKey)
	}
	if strings.ContainsAny(got.AuthorizedKey, "\r\n") {
		t.Fatalf("AuthorizedKey = %q, want one line", got.AuthorizedKey)
	}
}

func TestReadIdentityPublicKeyMatchesAGeneratedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	client := NewClient("example.com", 22, 0, path, "")
	var created []IdentityCreated
	client.SetIdentityCreatedCallback(func(c IdentityCreated) { created = append(created, c) })
	signer, err := client.generateIdentityKey(path)
	if err != nil {
		t.Fatalf("generateIdentityKey() error = %v", err)
	}

	first, err := ReadIdentityPublicKey(path)
	if err != nil {
		t.Fatalf("ReadIdentityPublicKey() error = %v", err)
	}
	second, err := ReadIdentityPublicKey(path)
	if err != nil {
		t.Fatalf("second ReadIdentityPublicKey() error = %v", err)
	}

	if first != second || first.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("read %+v then %+v, want the generated key both times", first, second)
	}
	want := []IdentityCreated{{Path: path, Fingerprint: first.Fingerprint}}
	if !slices.Equal(created, want) {
		t.Fatalf("announced %+v, want %+v", created, want)
	}
}

func TestReadIdentityPublicKeyDoesNotCreateAMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "id_ed25519")

	_, err := ReadIdentityPublicKey(path)

	if !errors.Is(err, ErrNoIdentityKey) {
		t.Fatalf("error = %v, want ErrNoIdentityKey", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("created %v; reading must not make a key", entries)
	}
}

func TestReadIdentityPublicKeyReportsAnEncryptedKey(t *testing.T) {
	path, _ := writeIdentity(t, "passphrase")
	if _, err := ReadIdentityPublicKey(path); !errors.Is(err, ErrIdentityKeyEncrypted) {
		t.Fatalf("error = %v, want ErrIdentityKeyEncrypted", err)
	}
}

func TestReadIdentityPublicKeyLeavesAnInvalidFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	const content = "not a key\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := ReadIdentityPublicKey(path)
	if err == nil || errors.Is(err, ErrNoIdentityKey) || errors.Is(err, ErrIdentityKeyEncrypted) {
		t.Fatalf("error = %v, want a parse error", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %v, want the path for context", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != content {
		t.Fatalf("file now %q, %v; it must not change", data, err)
	}
}

func TestReadIdentityPublicKeyReportsAnUnreadablePath(t *testing.T) {
	_, err := ReadIdentityPublicKey(t.TempDir()) // A directory.
	if err == nil || errors.Is(err, ErrNoIdentityKey) {
		t.Fatalf("error = %v, want a read error", err)
	}
}
