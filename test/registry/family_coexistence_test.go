// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package registry_test pins the registry-family invariant introduced by the
// qualified-family refactor: the native "ed25519" key type and the APlane
// Ed25519 LogicSig base "aplane.ed25519.v1" must coexist in one process without
// competing for the same keygen/mnemonic/metadata/signing registry slot. Before
// the refactor the LogicSig base used the bare family "ed25519lsig"; it now uses
// the qualified family "aplane.ed25519", distinct from native "ed25519".
package registry_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/mnemonic"

	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

func registerAll() {
	// Same order as cmd/apsigner/providers.go. Both are idempotent.
	lsigsignerreg.RegisterSigner()
	ed25519signerreg.RegisterSigner()
}

const (
	nativeEd25519 = "ed25519"
	lsigEd25519   = "aplane.ed25519.v1"

	nativeEd25519Family = "ed25519"
	lsigEd25519Family   = "aplane.ed25519"
)

// TestNativeEd25519AndLogicSigBaseCoexist is the core guard for the refactor:
// the two Ed25519-flavored key types resolve to distinct generators, mnemonic
// handlers, and metadata, with the LogicSig base on the qualified family.
func TestNativeEd25519AndLogicSigBaseCoexist(t *testing.T) {
	registerAll()

	// RoutingFamily keeps them in separate registry slots.
	if got := logicsigdsa.RoutingFamily(lsigEd25519); got != lsigEd25519Family {
		t.Fatalf("RoutingFamily(%q) = %q, want %q", lsigEd25519, got, lsigEd25519Family)
	}

	// Key generators resolve, and to different families (no collision).
	nativeGen, err := keygen.GetGenerator(nativeEd25519)
	if err != nil {
		t.Fatalf("GetGenerator(%q): %v", nativeEd25519, err)
	}
	lsigGen, err := keygen.GetGenerator(lsigEd25519)
	if err != nil {
		t.Fatalf("GetGenerator(%q): %v", lsigEd25519, err)
	}
	if nativeGen.Family() != nativeEd25519Family {
		t.Errorf("native generator Family() = %q, want %q", nativeGen.Family(), nativeEd25519Family)
	}
	if lsigGen.Family() != lsigEd25519Family {
		t.Errorf("lsig generator Family() = %q, want %q", lsigGen.Family(), lsigEd25519Family)
	}
	if nativeGen.Family() == lsigGen.Family() {
		t.Fatalf("native and lsig generators share family %q — collision", nativeGen.Family())
	}

	// Metadata resolves to distinct families.
	nativeMeta, err := algorithm.GetMetadata(nativeEd25519)
	if err != nil {
		t.Fatalf("GetMetadata(%q): %v", nativeEd25519, err)
	}
	lsigMeta, err := algorithm.GetMetadata(lsigEd25519)
	if err != nil {
		t.Fatalf("GetMetadata(%q): %v", lsigEd25519, err)
	}
	if nativeMeta.Family() != nativeEd25519Family || lsigMeta.Family() != lsigEd25519Family {
		t.Fatalf("metadata families = (%q, %q), want (%q, %q)",
			nativeMeta.Family(), lsigMeta.Family(), nativeEd25519Family, lsigEd25519Family)
	}

	// Mnemonic handlers resolve for both; native mnemonic import still works.
	nativeHandler, err := mnemonic.GetHandler(nativeEd25519)
	if err != nil {
		t.Fatalf("GetHandler(%q): %v", nativeEd25519, err)
	}
	lsigHandler, err := mnemonic.GetHandler(lsigEd25519)
	if err != nil {
		t.Fatalf("GetHandler(%q): %v", lsigEd25519, err)
	}
	if nativeHandler.Family() == lsigHandler.Family() {
		t.Fatalf("native and lsig mnemonic handlers share family %q — collision", nativeHandler.Family())
	}
}

// TestOldEd25519LsigKeyTypeIsGone confirms the renamed key type is no longer
// registered under its pre-refactor identifier.
func TestOldEd25519LsigKeyTypeIsGone(t *testing.T) {
	registerAll()

	if logicsigdsa.IsRegistered("aplane.ed25519lsig.v1") {
		t.Fatal("aplane.ed25519lsig.v1 is still registered; it was renamed to aplane.ed25519.v1")
	}
	if !logicsigdsa.IsRegistered(lsigEd25519) {
		t.Fatalf("%q is not registered", lsigEd25519)
	}
}
