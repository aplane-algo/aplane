// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// keyBytesWatch records the private key bytes aplane holds while a test runs:
// what was read from key files, what was written to them, and the raw keys
// generated.
type keyBytesWatch struct {
	read, written, generated [][]byte
}

func watchKeyBytes(t *testing.T) *keyBytesWatch {
	t.Helper()
	w := &keyBytesWatch{}
	read, write, generate := readKeyFile, writeNewKeyFile, generateEd25519Key
	readKeyFile = func(name string) ([]byte, error) {
		data, err := read(name)
		if err == nil {
			w.read = append(w.read, data)
		}
		return data, err
	}
	writeNewKeyFile = func(path string, pemBytes []byte) error {
		w.written = append(w.written, pemBytes)
		return write(path, pemBytes)
	}
	generateEd25519Key = func(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
		pub, priv, err := generate(r)
		w.generated = append(w.generated, priv)
		return pub, priv, err
	}
	t.Cleanup(func() { readKeyFile, writeNewKeyFile, generateEd25519Key = read, write, generate })
	return w
}

func assertAllZeroed(t *testing.T, what string, buffers [][]byte, want int) {
	t.Helper()
	if len(buffers) != want {
		t.Fatalf("%s: %d buffers, want %d", what, len(buffers), want)
	}
	for i, b := range buffers {
		if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("%s: buffer %d was left holding key material", what, i)
		}
	}
}

// assertSignerWorks checks that a signer still signs with the key stored at
// path: zeroing aplane's copies must not touch the signer's own.
func assertSignerWorks(t *testing.T, signer ssh.Signer, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.PublicKey().Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("signer does not match the stored key")
	}
	message := []byte("aplane key zeroing")
	signature, err := signer.Sign(rand.Reader, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := stored.PublicKey().Verify(message, signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// Creating a client identity or a host key zeroes the raw key and the PEM
// aplane wrote, and the signer it returns still signs.
func TestGeneratedKeysZeroThePrivateBytesAplaneHolds(t *testing.T) {
	for _, tt := range []struct {
		name     string
		generate func(path string) (ssh.Signer, error)
	}{
		{"client identity", func(path string) (ssh.Signer, error) {
			return NewClient("example.com", 22, path, "").generateIdentityKey(path)
		}},
		{"host key", loadOrGenerateHostKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			watch := watchKeyBytes(t)
			path := filepath.Join(t.TempDir(), "key")
			signer, err := tt.generate(path)
			if err != nil {
				t.Fatal(err)
			}
			assertAllZeroed(t, "generated key", watch.generated, 1)
			assertAllZeroed(t, "written PEM", watch.written, 1)
			assertSignerWorks(t, signer, path)
		})
	}
}

// Loading a client identity or a host key from disk zeroes the bytes read once
// they are parsed.
func TestLoadedKeysZeroTheBytesRead(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		load func(t *testing.T, path string)
	}{
		{"client identity", func(t *testing.T, path string) {
			method, _, err := NewClient("example.com", 22, path, "").authMethod(nil)
			if err != nil || method == nil {
				t.Fatalf("authMethod() = %v, %v", method, err)
			}
		}},
		{"host key", func(t *testing.T, path string) {
			signer, err := loadOrGenerateHostKey(path)
			if err != nil {
				t.Fatal(err)
			}
			assertSignerWorks(t, signer, path)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
				t.Fatal(err)
			}
			watch := watchKeyBytes(t)
			tt.load(t, path)
			assertAllZeroed(t, "key file bytes", watch.read, 1)
			if len(watch.generated) != 0 || len(watch.written) != 0 {
				t.Fatal("loading an existing key generated or wrote one")
			}
		})
	}
}
