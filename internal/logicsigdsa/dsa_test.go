// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package logicsigdsa_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func init() {
	// Register Falcon LogicSigDSA for tests
	v1.RegisterLogicSigDSA()
}

func TestFalcon1024V1ImplementsInterface(t *testing.T) {
	// Verify Falcon1024V1 implements LogicSigDSA
	var _ logicsigdsa.LogicSigDSA = &v1.Falcon1024V1{}
}

func TestFalcon1024V1Registration(t *testing.T) {
	dsa := logicsigdsa.Get("falcon1024-v1")
	if dsa == nil {
		t.Fatal("falcon1024-v1 not registered")
	}

	if dsa.KeyType() != "falcon1024-v1" {
		t.Errorf("KeyType = %q, want %q", dsa.KeyType(), "falcon1024-v1")
	}

	if dsa.CryptoSignatureSize() != 1280 {
		t.Errorf("CryptoSignatureSize = %d, want %d", dsa.CryptoSignatureSize(), 1280)
	}

	if dsa.MnemonicScheme() != "bip39" {
		t.Errorf("MnemonicScheme = %q, want %q", dsa.MnemonicScheme(), "bip39")
	}

	if dsa.MnemonicWordCount() != 24 {
		t.Errorf("MnemonicWordCount = %d, want %d", dsa.MnemonicWordCount(), 24)
	}

	if dsa.DisplayColor() != "33" {
		t.Errorf("DisplayColor = %q, want %q", dsa.DisplayColor(), "33")
	}
}

func TestGetKeyTypes(t *testing.T) {
	keyTypes := logicsigdsa.GetKeyTypes()

	found := false
	for _, kt := range keyTypes {
		if kt == "falcon1024-v1" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("falcon1024-v1 not in GetKeyTypes(): %v", keyTypes)
	}
}

func TestGetAll(t *testing.T) {
	all := logicsigdsa.GetAll()
	if len(all) == 0 {
		t.Fatal("GetAll() returned empty list")
	}

	found := false
	for _, dsa := range all {
		if dsa.KeyType() == "falcon1024-v1" {
			found = true
			break
		}
	}

	if !found {
		t.Error("falcon1024-v1 not in GetAll()")
	}
}

func TestFalcon1024V1GenerateAndDerive(t *testing.T) {
	// Configure algod client (required for DeriveLsig)
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}
	logicsigdsa.ConfigureAlgodClient(client)

	dsa := logicsigdsa.Get("falcon1024-v1")
	if dsa == nil {
		t.Fatal("falcon1024-v1 not registered")
	}

	// Generate a test seed (64 bytes from BIP-39)
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Generate keypair
	pub, priv, err := dsa.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if len(pub) != 1793 {
		t.Errorf("public key size = %d, want 1793", len(pub))
	}

	if len(priv) != 2305 {
		t.Errorf("private key size = %d, want 2305", len(priv))
	}

	// Derive LogicSig
	bytecode, addr, err := dsa.DeriveLsig(pub, nil)
	if err != nil {
		t.Fatalf("DeriveLsig failed: %v", err)
	}

	if len(bytecode) == 0 {
		t.Error("bytecode is empty")
	}

	if addr == "" {
		t.Error("address is empty")
	}

	// Verify address format (58 characters, starts with Algorand address prefix)
	if len(addr) != 58 {
		t.Errorf("address length = %d, want 58", len(addr))
	}

	t.Logf("Generated address: %s", addr)
	t.Logf("LogicSig bytecode size: %d bytes", len(bytecode))
}

func TestFalcon1024V1Sign(t *testing.T) {
	dsa := logicsigdsa.Get("falcon1024-v1")
	if dsa == nil {
		t.Fatal("falcon1024-v1 not registered")
	}

	// Generate a test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i * 2)
	}

	// Generate keypair
	_, priv, err := dsa.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Sign a message
	message := []byte("test message for signing")
	sig, err := dsa.Sign(priv, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("signature is empty")
	}

	// Falcon signatures are variable length, typically around 600-1280 bytes
	if len(sig) > 1280 {
		t.Errorf("signature too large: %d bytes", len(sig))
	}

	t.Logf("Signature size: %d bytes", len(sig))
}

func TestIsLogicSigType(t *testing.T) {
	tests := []struct {
		keyType string
		want    bool
	}{
		{"falcon1024-v1", true}, // Directly registered
		{"falcon1024", false},   // Family name (not registered, only versioned types are)
		{"ed25519", false},      // Not a LogicSig type
		{"nonexistent", false},  // Unknown type
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			got := logicsigdsa.IsLogicSigType(tt.keyType)
			if got != tt.want {
				t.Errorf("IsLogicSigType(%q) = %v, want %v", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestConfigureAlgodClient(t *testing.T) {
	// Create a mock algod client
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Call ConfigureAlgodClient - this should set the client on all configurable DSAs
	logicsigdsa.ConfigureAlgodClient(client)

	// Verify falcon1024-v1 (which implements AlgodConfigurable) is configured
	dsa := logicsigdsa.Get("falcon1024-v1")
	if dsa == nil {
		t.Fatal("falcon1024-v1 not registered")
	}

	// Verify it implements AlgodConfigurable
	if _, ok := dsa.(lsigprovider.AlgodConfigurable); !ok {
		t.Error("falcon1024-v1 should implement AlgodConfigurable")
	}

	// Test that DeriveLsig works (which requires the client for composed mode)
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pub, _, err := dsa.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// This should use the composed mode since algod client is now set
	bytecode, addr, err := dsa.DeriveLsig(pub, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() error: %v", err)
	}

	if len(bytecode) != 1805 {
		t.Errorf("Bytecode length = %d, want 1805", len(bytecode))
	}

	if addr == "" {
		t.Error("Address should not be empty")
	}

	t.Logf("Configured DSA derived address: %s", addr)
}
