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

// KeyringAtTerm wraps a known key as a single specified term. It is used to
// exercise target-term records before persisted multi-term roots are enabled.
func KeyringAtTerm(t *testing.T, term int64, termKey []byte) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyringFromTermKey(term, termKey)
	if err != nil {
		t.Fatalf("NewKeyringFromTermKey(): %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}

// KeyringWithTerms wraps known keys for historical and mixed-term tests.
func KeyringWithTerms(t *testing.T, currentTerm int64, terms map[int64][]byte) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyringFromTermKeys(currentTerm, terms)
	if err != nil {
		t.Fatalf("NewKeyringFromTermKeys(): %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}
