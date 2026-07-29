// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package cryptotest provides keyring fixtures for tests in other packages.
//
// It exists so the same fixture is not copied into every package that needs
// one: identical copies drift, and the failure mode is silent — one copy
// losing its cleanup leaks key material for the rest of the run.
package cryptotest

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
)

// Keyring wraps a raw term-1 key as a keyring, matching what the store holds
// once unlocked. The keyring is zeroed when the test finishes.
//
// Use it where a test already holds the key bytes it wrote a fixture with.
// Prefer crypto.OpenKeyringStore where the test has a real store on disk.
func Keyring(t *testing.T, masterKey []byte) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyringFromKey(masterKey)
	if err != nil {
		t.Fatalf("NewKeyringFromKey(): %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}

// NewKeyring returns a fresh single-term keyring, zeroed when the test ends.
func NewKeyring(t *testing.T) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring(): %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}
