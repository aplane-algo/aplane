// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func TestFalconBase(t *testing.T) {
	base := family.FalconBase

	if base.Name() != family.Name {
		t.Errorf("Name() = %q, want %q", base.Name(), family.Name)
	}

	if base.PublicKeySize() != family.PublicKeySize {
		t.Errorf("PublicKeySize() = %d, want %d", base.PublicKeySize(), family.PublicKeySize)
	}

	if base.PrivateKeySize() != family.PrivateKeySize {
		t.Errorf("PrivateKeySize() = %d, want %d", base.PrivateKeySize(), family.PrivateKeySize)
	}

	if base.CryptoSignatureSize() != family.MaxSignatureSize {
		t.Errorf("CryptoSignatureSize() = %d, want %d", base.CryptoSignatureSize(), family.MaxSignatureSize)
	}

	if base.MnemonicScheme() != "bip39" {
		t.Errorf("MnemonicScheme() = %q, want %q", base.MnemonicScheme(), "bip39")
	}

	if base.MnemonicWordCount() != 24 {
		t.Errorf("MnemonicWordCount() = %d, want %d", base.MnemonicWordCount(), 24)
	}
}

func TestFalconHashlockV1Identity(t *testing.T) {
	p := FalconHashlockV1

	if p.KeyType() != "falcon1024-hashlock-v1" {
		t.Errorf("KeyType() = %q, want %q", p.KeyType(), "falcon1024-hashlock-v1")
	}

	if p.Family() != family.Name {
		t.Errorf("Family() = %q, want %q", p.Family(), family.Name)
	}

	if p.Version() != 1 {
		t.Errorf("Version() = %d, want 1", p.Version())
	}

	if p.Category() != lsigprovider.CategoryDSALsig {
		t.Errorf("Category() = %q, want %q", p.Category(), lsigprovider.CategoryDSALsig)
	}

	if !strings.Contains(p.DisplayName(), "Hashlock") {
		t.Errorf("DisplayName() = %q, should contain 'Hashlock'", p.DisplayName())
	}
}

func TestFalconHashlockV1Parameters(t *testing.T) {
	p := FalconHashlockV1

	// Check creation params
	params := p.CreationParams()
	if len(params) != 1 {
		t.Fatalf("CreationParams() len = %d, want 1", len(params))
	}
	if params[0].Name != "hash" {
		t.Errorf("CreationParams()[0].Name = %q, want %q", params[0].Name, "hash")
	}

	// Check runtime args
	args := p.RuntimeArgs()
	if len(args) != 1 {
		t.Fatalf("RuntimeArgs() len = %d, want 1", len(args))
	}
	if args[0].Name != "preimage" {
		t.Errorf("RuntimeArgs()[0].Name = %q, want %q", args[0].Name, "preimage")
	}
}

func TestFalconHashlockV1Validation(t *testing.T) {
	p := FalconHashlockV1

	// Valid hash
	validHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err := p.ValidateCreationParams(map[string]string{"hash": validHash}); err != nil {
		t.Errorf("ValidateCreationParams() with valid hash: %v", err)
	}

	// Missing hash
	if err := p.ValidateCreationParams(map[string]string{}); err == nil {
		t.Error("ValidateCreationParams() with missing hash should fail")
	}
}

func TestFalconHashlockV1GenerateTEAL(t *testing.T) {
	p := FalconHashlockV1

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := p.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Generate TEAL
	preimage := []byte("secret preimage")
	hash := sha256.Sum256(preimage)
	hashHex := hex.EncodeToString(hash[:])

	teal, err := p.GenerateTEAL(pubKey, map[string]string{"hash": hashHex})
	if err != nil {
		t.Fatalf("GenerateTEAL() error: %v", err)
	}

	// Verify TEAL contains expected elements
	if !strings.Contains(teal, "#pragma version 12") {
		t.Error("TEAL should contain '#pragma version 12'")
	}
	if !strings.Contains(teal, "bytecblock") {
		t.Error("TEAL should contain 'bytecblock'")
	}
	if !strings.Contains(teal, "RekeyTo") {
		t.Error("TEAL should contain 'RekeyTo'")
	}
	if !strings.Contains(teal, "CloseRemainderTo") {
		t.Error("TEAL should contain 'CloseRemainderTo'")
	}
	if !strings.Contains(teal, "sha256") {
		t.Error("TEAL should contain 'sha256'")
	}
	if !strings.Contains(teal, "falcon_verify") {
		t.Error("TEAL should contain 'falcon_verify'")
	}
	if !strings.Contains(teal, "0x"+hashHex) {
		t.Error("TEAL should contain the hash value with 0x prefix")
	}
	if !strings.Contains(teal, hex.EncodeToString(pubKey)) {
		t.Error("TEAL should contain the public key")
	}

	t.Logf("Generated TEAL (%d chars):\n%s", len(teal), teal[:500]+"...")
}

func TestFalconHashlockV1Sign(t *testing.T) {
	p := FalconHashlockV1

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	_, privKey, err := p.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Test signing
	message := []byte("test message to sign")
	signature, err := p.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}

	if len(signature) > family.MaxSignatureSize {
		t.Errorf("signature size %d exceeds max %d", len(signature), family.MaxSignatureSize)
	}

	t.Logf("Signature length: %d bytes", len(signature))
}

func TestFalconHashlockV1DeriveLsigRequiresClient(t *testing.T) {
	// Create a fresh provider without algod client
	p := NewComposedDSA(ComposedDSAConfig{
		KeyType:    "test-hashlock",
		FamilyName: family.Name,
		Version:    1,
		Base:       family.FalconBase,
	})

	seed := make([]byte, 64)
	pubKey, _, _ := p.GenerateKeypair(seed)

	// DeriveLsig should fail without client
	_, _, err := p.DeriveLsig(pubKey, map[string]string{"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
	if err == nil {
		t.Error("DeriveLsig() should fail without algod client")
	}
	if !strings.Contains(err.Error(), "algod client not set") {
		t.Errorf("Expected 'algod client not set' error, got: %v", err)
	}
}

// TestFalconHashlockV1DeriveLsig tests full derivation with a real algod client.
func TestFalconHashlockV1DeriveLsig(t *testing.T) {
	// Create algod client for mainnet (read-only operations)
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Test with the global FalconHashlockV1 provider
	FalconHashlockV1.SetAlgodClient(client)

	// Generate keypair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := FalconHashlockV1.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive with valid hash
	preimage := []byte("secret preimage")
	hash := sha256.Sum256(preimage)
	hashHex := hex.EncodeToString(hash[:])

	bytecode, address, err := FalconHashlockV1.DeriveLsig(pubKey, map[string]string{"hash": hashHex})
	if err != nil {
		t.Fatalf("DeriveLsig() error: %v", err)
	}

	if len(bytecode) == 0 {
		t.Error("DeriveLsig() returned empty bytecode")
	}

	if address == "" {
		t.Error("DeriveLsig() returned empty address")
	}

	// Verify address is valid Algorand address format
	if len(address) != 58 {
		t.Errorf("address length = %d, want 58", len(address))
	}

	t.Logf("Generated address: %s", address)
	t.Logf("Bytecode length: %d bytes", len(bytecode))
}

// TestFalconHashlockV1AddressDeterminism verifies same inputs produce same address.
func TestFalconHashlockV1AddressDeterminism(t *testing.T) {
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	FalconHashlockV1.SetAlgodClient(client)

	// Generate keypair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(42)
	}

	pubKey, _, err := FalconHashlockV1.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Derive twice with same params
	_, addr1, err := FalconHashlockV1.DeriveLsig(pubKey, map[string]string{"hash": hashHex})
	if err != nil {
		t.Fatalf("DeriveLsig() first call error: %v", err)
	}

	_, addr2, err := FalconHashlockV1.DeriveLsig(pubKey, map[string]string{"hash": hashHex})
	if err != nil {
		t.Fatalf("DeriveLsig() second call error: %v", err)
	}

	if addr1 != addr2 {
		t.Errorf("Address derivation not deterministic: %s != %s", addr1, addr2)
	}
}

// TestFalconHashlockV1DifferentHashDifferentAddress verifies different hashes produce different addresses.
func TestFalconHashlockV1DifferentHashDifferentAddress(t *testing.T) {
	client, err := algod.MakeClient("https://mainnet-api.algonode.cloud", "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	FalconHashlockV1.SetAlgodClient(client)

	// Generate keypair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(42)
	}

	pubKey, _, err := FalconHashlockV1.GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	hash1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hash2 := "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	_, addr1, err := FalconHashlockV1.DeriveLsig(pubKey, map[string]string{"hash": hash1})
	if err != nil {
		t.Fatalf("DeriveLsig() with hash1 error: %v", err)
	}

	_, addr2, err := FalconHashlockV1.DeriveLsig(pubKey, map[string]string{"hash": hash2})
	if err != nil {
		t.Fatalf("DeriveLsig() with hash2 error: %v", err)
	}

	if addr1 == addr2 {
		t.Error("Different hashes should produce different addresses")
	}
}
