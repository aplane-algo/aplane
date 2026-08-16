// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func TestFalcon1024V1_KeyType(t *testing.T) {
	f := &Falcon1024V1{}
	if f.KeyType() != "aplane.falcon1024.v1" {
		t.Errorf("KeyType() = %q, want %q", f.KeyType(), "aplane.falcon1024.v1")
	}
}

func TestFalcon1024V1_Family(t *testing.T) {
	f := &Falcon1024V1{}
	if f.RoutingFamily() != family.Name {
		t.Errorf("RoutingFamily() = %q, want %q", f.RoutingFamily(), family.Name)
	}
}

func TestFalcon1024V1_Version(t *testing.T) {
	f := &Falcon1024V1{}
	if f.Version() != 1 {
		t.Errorf("Version() = %d, want 1", f.Version())
	}
}

func TestFalcon1024V1GenerateTEALUsesV13AutoSalt(t *testing.T) {
	f := &Falcon1024V1{}
	pubKey := make([]byte, family.PublicKeySize)

	teal, err := f.GenerateTEAL(pubKey, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, "#pragma version 13") {
		t.Fatalf("GenerateTEAL() missing TEAL v13:\n%s", teal)
	}
	preamble, _ := lsigsalt.StylePushbytes.SourcePreamble()
	if strings.Contains(teal, "bytecblock 0x00") || strings.Contains(teal, strings.TrimSpace(preamble)) || strings.Contains(teal, "Counter byte") {
		t.Fatalf("GenerateTEAL() contains an APlane manual salt anchor:\n%s", teal)
	}
}

func TestFalcon1024V1CompilerAutoSaltGolden(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	f := &Falcon1024V1{}
	pubKey := falconTestPublicKey(t)
	f.SetAlgodClient(client)
	derived, err := f.DeriveLsigWithSalt(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if !derived.CompilerAutoSalted || lsigsalt.IsOnCurve(derived.Address) {
		t.Fatalf("derived result = %+v, want compiler-auto-salted off-curve bytecode", derived)
	}
	if len(derived.Bytecode) != 1801 || derived.Address.String() != "MS4DNTRYOOLQZ4UXK5APVE4XEWMU4CDTUYGOO5UQCWLONDRUP56DZDOBVA" {
		t.Fatalf("compiler golden = %d bytes / %s", len(derived.Bytecode), derived.Address.String())
	}
}

func TestFalcon1024V1_DeriveLsig_RequiresAlgod(t *testing.T) {
	f := &Falcon1024V1{} // No algod client set

	seed := make([]byte, 64)
	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Should fail without algod client
	_, _, err = f.DeriveLsig(context.Background(), pubKey, nil)
	if err == nil {
		t.Error("DeriveLsig() should fail without algod client")
	}
	if !strings.Contains(err.Error(), "algod client not set") {
		t.Errorf("Expected 'algod client not set' error, got: %v", err)
	}
}

func falconTestPublicKey(t *testing.T) []byte {
	t.Helper()

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return pubKey
}

func TestFalcon1024V1_DeriveLsig(t *testing.T) {
	// Create algod client
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
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

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive LogicSig
	bytecode, addr, err := f.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() error: %v", err)
	}

	if len(bytecode) != 1801 {
		t.Errorf("Bytecode length = %d, want 1801", len(bytecode))
	}

	if addr == "" {
		t.Error("Address should not be empty")
	}
	salted, err := f.DeriveLsigWithSalt(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error: %v", err)
	}
	if !bytes.Equal(bytecode, salted.Bytecode) || addr != salted.Address.String() {
		t.Fatalf("DeriveLsigWithSalt() = (%x, %s), want (%x, %s)", salted.Bytecode, salted.Address.String(), bytecode, addr)
	}
	if lsigsalt.IsOnCurve(salted.Address) {
		t.Fatalf("DeriveLsigWithSalt() returned on-curve address %s", salted.Address.String())
	}
	if !salted.CompilerAutoSalted {
		t.Fatal("DeriveLsigWithSalt() did not identify compiler auto-salting")
	}

	// Verify determinism
	bytecode2, addr2, err := f.DeriveLsig(context.Background(), pubKey, nil)
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

// TestZeroSuffixMatchesStandardFalcon verifies that a composed provider
// with no TEAL suffix produces identical bytecode to standard aplane.falcon1024.v1.
func TestZeroSuffixMatchesStandardFalcon(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
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

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	standard := &Falcon1024V1{}
	standard.SetAlgodClient(client)
	standardBytecode, standardAddr, err := standard.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("standard DeriveLsig() error: %v", err)
	}

	// Derive using composed with no TEAL suffix
	composedBytecode, composedAddr, err := pureComposed.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("Composed DeriveLsig() error: %v", err)
	}

	// Compare
	t.Logf("Standard aplane.falcon1024.v1:")
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
