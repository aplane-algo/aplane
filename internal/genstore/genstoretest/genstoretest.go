// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package genstoretest provides test fixtures for generation-based stores.
package genstoretest

import (
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var defaultPassphrase = []byte("genstoretest-atomic-root-passphrase")

// MintFirst mints an identity's first empty atomic-root generation and returns
// paths bound to its authenticated selection. It is idempotent.
func MintFirst(t testing.TB, paths storepaths.Paths) storepaths.Paths {
	t.Helper()
	if active, kr, err := genstore.ResolveStoreRoot(paths, defaultPassphrase); err == nil {
		defer kr.Zero()
		return BindActive(t, paths, active)
	}
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	defer kr.Zero()
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	active, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: generationID, FirstGeneration: true,
		InitialPassphrase: defaultPassphrase, Integrity: kr,
		Operation: "store-initialize", OperationID: "init-" + generationID,
		CreatedAt: time.Unix(1_785_200_000, 0), Apply: ApplyAuthorityPlaceholders,
	})
	if err != nil {
		t.Fatalf("Mint(first generation): %v", err)
	}
	return BindActive(t, paths, active)
}

// MintFirstAtomic creates the sole supported store-root layout and returns
// its open keyring plus selected generation. The caller owns and must zero
// the keyring.
func MintFirstAtomic(t testing.TB, paths storepaths.Paths, passphrase []byte) (*crypto.Keyring, storepaths.GenPaths) {
	t.Helper()
	if active, kr, err := genstore.ResolveStoreRoot(paths, passphrase); err == nil {
		return kr, active
	}
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		kr.Zero()
		t.Fatalf("NewGenerationID: %v", err)
	}
	active, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: generationID, FirstGeneration: true,
		InitialPassphrase: passphrase, Integrity: kr,
		Operation: "store-initialize", OperationID: "init-" + generationID,
		CreatedAt: time.Unix(1_785_200_000, 0), Apply: ApplyAuthorityPlaceholders,
	})
	if err != nil {
		kr.Zero()
		t.Fatalf("Mint(first atomic generation): %v", err)
	}
	return kr, active
}

// BindActive returns paths carrying an already-authenticated generation
// capability for APIs that accept Paths instead of GenPaths.
func BindActive(t testing.TB, paths storepaths.Paths, active storepaths.GenPaths) storepaths.Paths {
	t.Helper()
	bound, err := paths.BindActive(active)
	if err != nil {
		t.Fatalf("BindActive: %v", err)
	}
	return bound
}

// BindDefault opens a MintFirst fixture and returns its authenticated path
// capability. It is intended for test adapters that cannot carry testing.TB.
func BindDefault(paths storepaths.Paths) (storepaths.Paths, error) {
	active, kr, err := genstore.ResolveStoreRoot(paths, defaultPassphrase)
	if err != nil {
		return storepaths.Paths{}, err
	}
	defer kr.Zero()
	return paths.BindActive(active)
}

// ApplyAuthorityPlaceholders supplies structurally complete, deliberately
// unauthenticated authority members to low-level tests that do not exercise
// policy or node-role verification. Production initialization must create
// authenticated members with policy and noderole APIs instead.
func ApplyAuthorityPlaceholders(staged storepaths.GenPaths) error {
	for _, path := range []string{
		staged.PolicyPath(),
		staged.PolicyIntegritySidecar(),
		staged.NodeRoleIntegritySidecar(),
	} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Active resolves an identity's current generation for tests that exercise an
// API whose caller already owns active-path resolution.
func Active(t testing.TB, paths storepaths.Paths) storepaths.GenPaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		var bound storepaths.Paths
		bound, err = BindDefault(paths)
		if err == nil {
			active, err = genstore.ResolveActive(bound)
		}
	}
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	gen, ok := active.(storepaths.GenPaths)
	if !ok {
		t.Fatalf("ResolveActive returned %T, want GenPaths", active)
	}
	return gen
}
