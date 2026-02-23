// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package v1

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	reference "github.com/aplane-algo/aplane/lsig/falcon1024/v1/reference"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

func TestFalcon1024V1_KeyType(t *testing.T) {
	f := &Falcon1024V1{}
	if f.KeyType() != "falcon1024-v1" {
		t.Errorf("KeyType() = %q, want %q", f.KeyType(), "falcon1024-v1")
	}
}

func TestFalcon1024V1_Family(t *testing.T) {
	f := &Falcon1024V1{}
	if f.Family() != family.Name {
		t.Errorf("Family() = %q, want %q", f.Family(), family.Name)
	}
}

func TestFalcon1024V1_Version(t *testing.T) {
	f := &Falcon1024V1{}
	if f.Version() != 1 {
		t.Errorf("Version() = %d, want 1", f.Version())
	}
}

func TestFalcon1024V1_DeriveLsig_RequiresAlgod(t *testing.T) {
	f := &Falcon1024V1{} // No algod client set

	seed := make([]byte, 64)
	pubKey, _, err := f.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Should fail without algod client
	_, _, err = f.DeriveLsig(pubKey, nil)
	if err == nil {
		t.Error("DeriveLsig() should fail without algod client")
	}
	if !strings.Contains(err.Error(), "algod client not set") {
		t.Errorf("Expected 'algod client not set' error, got: %v", err)
	}
}

func TestFalcon1024V1_DeriveLsig(t *testing.T) {
	// Create algod client
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	f := &Falcon1024V1{}
	f.SetAlgodClient(client)

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := f.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive LogicSig
	bytecode, addr, err := f.DeriveLsig(pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() error: %v", err)
	}

	if len(bytecode) != 1805 {
		t.Errorf("Bytecode length = %d, want 1805", len(bytecode))
	}

	if addr == "" {
		t.Error("Address should not be empty")
	}

	// Verify determinism
	bytecode2, addr2, err := f.DeriveLsig(pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() second call error: %v", err)
	}

	if addr != addr2 {
		t.Errorf("Address derivation not deterministic: %s != %s", addr, addr2)
	}

	if !bytes.Equal(bytecode, bytecode2) {
		t.Error("Bytecode derivation not deterministic")
	}

	t.Logf("Derived address: %s", addr)
}

// TestFalcon1024V1_MatchesPrecompiledV1 verifies that the composed system produces
// identical bytecode to the frozen precompiled v1 derivation.
func TestFalcon1024V1_MatchesPrecompiledV1(t *testing.T) {
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	f := &Falcon1024V1{}
	f.SetAlgodClient(client)

	pubKey, _, err := f.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive using Falcon1024V1 (composed system)
	composedBytecode, composedAddr, err := f.DeriveLsig(pubKey, nil)
	if err != nil {
		t.Fatalf("Composed DeriveLsig() error: %v", err)
	}

	// Derive using precompiled v1 directly (frozen derivation)
	var pub falcongo.PublicKey
	copy(pub[:], pubKey)
	lsigAcct, err := reference.DerivePQLogicSig(pub)
	if err != nil {
		t.Fatalf("Precompiled DerivePQLogicSig() error: %v", err)
	}
	precompiledBytecode := lsigAcct.Lsig.Logic
	precompiledAddrTyped, err := lsigAcct.Address()
	if err != nil {
		t.Fatalf("Address() error: %v", err)
	}
	precompiledAddr := precompiledAddrTyped.String()

	// Compare
	t.Logf("Precompiled v1: %s (%d bytes)", precompiledAddr, len(precompiledBytecode))
	t.Logf("Composed:       %s (%d bytes)", composedAddr, len(composedBytecode))

	if precompiledAddr != composedAddr {
		t.Errorf("Addresses differ:\n  precompiled: %s\n  composed: %s", precompiledAddr, composedAddr)
	}

	if !bytes.Equal(precompiledBytecode, composedBytecode) {
		t.Errorf("Bytecode differs:\n  precompiled len: %d\n  composed len: %d",
			len(precompiledBytecode), len(composedBytecode))
	}
}

// TestZeroSuffixMatchesStandardFalcon verifies that a composed provider
// with no TEAL suffix produces identical bytecode to standard falcon1024-v1.
func TestZeroSuffixMatchesStandardFalcon(t *testing.T) {
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Create a composed provider with NO TEAL suffix (using the factory)
	pureComposed := newFalconV1Composed()
	pureComposed.SetAlgodClient(client)

	// Generate keypair from same seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := family.FalconBase.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive using precompiled v1 (the original frozen derivation)
	var pub falcongo.PublicKey
	copy(pub[:], pubKey)
	lsigAcct, err := reference.DerivePQLogicSig(pub)
	if err != nil {
		t.Fatalf("Standard DerivePQLogicSig() error: %v", err)
	}
	standardBytecode := lsigAcct.Lsig.Logic
	standardAddrTyped, err := lsigAcct.Address()
	if err != nil {
		t.Fatalf("Address() error: %v", err)
	}
	standardAddr := standardAddrTyped.String()

	// Derive using composed with no TEAL suffix
	composedBytecode, composedAddr, err := pureComposed.DeriveLsig(pubKey, nil)
	if err != nil {
		t.Fatalf("Composed DeriveLsig() error: %v", err)
	}

	// Compare
	t.Logf("Standard falcon1024-v1 (precompiled):")
	t.Logf("  Address: %s", standardAddr)
	t.Logf("  Bytecode length: %d bytes", len(standardBytecode))
	t.Logf("  First 20 bytes: %x", standardBytecode[:20])

	t.Logf("Composed with no TEAL suffix:")
	t.Logf("  Address: %s", composedAddr)
	t.Logf("  Bytecode length: %d bytes", len(composedBytecode))
	t.Logf("  First 20 bytes: %x", composedBytecode[:20])

	if standardAddr != composedAddr {
		t.Errorf("Addresses differ:\n  standard: %s\n  composed: %s", standardAddr, composedAddr)
	}

	if !bytes.Equal(standardBytecode, composedBytecode) {
		t.Errorf("Bytecode differs:\n  standard len: %d\n  composed len: %d",
			len(standardBytecode), len(composedBytecode))
	}
}
