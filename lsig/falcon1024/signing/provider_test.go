// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falcon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signing"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1/reference"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// testFalcon1024V1 is a minimal DSA implementation for tests.
// Implements both LogicSigDSA and LSigProvider interfaces.
type testFalcon1024V1 struct{}

// LogicSigDSA interface
func (f *testFalcon1024V1) KeyType() string          { return "falcon1024-v1" }
func (f *testFalcon1024V1) Family() string           { return "falcon1024" }
func (f *testFalcon1024V1) Version() int             { return 1 }
func (f *testFalcon1024V1) CryptoSignatureSize() int { return 1280 }
func (f *testFalcon1024V1) MnemonicScheme() string   { return "bip39" }
func (f *testFalcon1024V1) MnemonicWordCount() int   { return 24 }
func (f *testFalcon1024V1) DisplayColor() string     { return "33" }

// LSigProvider interface
func (f *testFalcon1024V1) Category() string    { return lsigprovider.CategoryDSALsig }
func (f *testFalcon1024V1) DisplayName() string { return "Falcon-1024" }
func (f *testFalcon1024V1) Description() string { return "Test DSA" }
func (f *testFalcon1024V1) CreationParams() []lsigprovider.ParameterDef {
	return nil
}
func (f *testFalcon1024V1) ValidateCreationParams(params map[string]string) error {
	return nil
}
func (f *testFalcon1024V1) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}
func (f *testFalcon1024V1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required")
	}
	return [][]byte{signature}, nil
}

func (f *testFalcon1024V1) GenerateKeypair(seed []byte) ([]byte, []byte, error) {
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, err
	}
	return kp.PublicKey[:], kp.PrivateKey[:], nil
}

func (f *testFalcon1024V1) DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error) {
	_ = params // Pure Falcon ignores params
	var pub falcongo.PublicKey
	copy(pub[:], publicKey)
	lsigAcct, err := v1.DerivePQLogicSig(pub)
	if err != nil {
		return nil, "", err
	}
	addr, err := lsigAcct.Address()
	if err != nil {
		return nil, "", err
	}
	return lsigAcct.Lsig.Logic, addr.String(), nil
}

func (f *testFalcon1024V1) Sign(privateKey []byte, message []byte) ([]byte, error) {
	var priv falcongo.PrivateKey
	copy(priv[:], privateKey)
	var pub falcongo.PublicKey // Empty, not used for signing
	kp := falcongo.KeyPair{PublicKey: pub, PrivateKey: priv}
	sig, err := kp.Sign(message)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func init() {
	// Register Falcon LogicSigDSA and signing provider for tests
	// Uses local test implementation to avoid import cycle
	if logicsigdsa.Get("falcon1024-v1") == nil {
		logicsigdsa.Register(&testFalcon1024V1{})
	}
	RegisterProvider()
}

func TestFalconProvider_KeyType(t *testing.T) {
	p := &FalconProvider{}
	if p.Family() != "falcon1024" {
		t.Errorf("KeyType() = %v, want falcon1024", p.Family())
	}
}

func TestFalconProvider_LoadKeysFromData_Valid(t *testing.T) {
	p := &FalconProvider{}

	// Generate a test key pair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	// Create key data JSON with versioned key type
	keyData := utilkeys.KeyPair{
		KeyType:       "falcon1024-v1",
		PublicKeyHex:  hex.EncodeToString(kp.PublicKey[:]),
		PrivateKeyHex: hex.EncodeToString(kp.PrivateKey[:]),
	}
	jsonData, _ := json.Marshal(keyData)

	// Load keys
	keyMaterial, err := p.LoadKeysFromData(jsonData)
	if err != nil {
		t.Fatalf("LoadKeysFromData() error = %v", err)
	}

	if keyMaterial.Type != "falcon1024-v1" {
		t.Errorf("LoadKeysFromData() Type = %v, want falcon1024-v1", keyMaterial.Type)
	}

	// Verify the loaded key material has private key bytes
	loadedKM, ok := keyMaterial.Value.(*FalconKeyMaterial)
	if !ok {
		t.Fatal("LoadKeysFromData() Value is not a *FalconKeyMaterial")
	}

	// Verify private key was loaded (should match length of original)
	if len(loadedKM.PrivateKey) != len(kp.PrivateKey) {
		t.Errorf("LoadKeysFromData() private key length = %d, want %d", len(loadedKM.PrivateKey), len(kp.PrivateKey))
	}
}

func TestFalconProvider_LoadKeysFromData_InvalidJSON(t *testing.T) {
	p := &FalconProvider{}

	_, err := p.LoadKeysFromData([]byte("not json"))
	if err == nil {
		t.Error("LoadKeysFromData() expected error for invalid JSON")
	}
}

func TestFalconProvider_LoadKeysFromData_InvalidHex(t *testing.T) {
	p := &FalconProvider{}

	keyData := utilkeys.KeyPair{
		PublicKeyHex:  "not valid hex",
		PrivateKeyHex: "also not valid",
	}
	jsonData, _ := json.Marshal(keyData)

	_, err := p.LoadKeysFromData(jsonData)
	if err == nil {
		t.Error("LoadKeysFromData() expected error for invalid hex")
	}
}

func TestFalconProvider_SignMessage(t *testing.T) {
	p := &FalconProvider{}

	// Generate a test key pair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	// Use FalconKeyMaterial with raw private key bytes and versioned type
	keyMaterial := &signing.KeyMaterial{
		Type: "falcon1024-v1",
		Value: &FalconKeyMaterial{
			PrivateKey: kp.PrivateKey[:],
		},
	}

	message := []byte("test message to sign")

	signature, err := p.SignMessage(keyMaterial, message)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("SignMessage() returned empty signature")
	}
}

func TestFalconProvider_SignMessage_WrongKeyType(t *testing.T) {
	p := &FalconProvider{}

	keyMaterial := &signing.KeyMaterial{
		Type:  "ed25519", // Wrong type
		Value: &FalconKeyMaterial{},
	}

	_, err := p.SignMessage(keyMaterial, []byte("message"))
	if err == nil {
		t.Error("SignMessage() expected error for wrong key type")
	}
}

func TestFalconProvider_SignMessage_NilKeyMaterial(t *testing.T) {
	p := &FalconProvider{}

	_, err := p.SignMessage(nil, []byte("message"))
	if err == nil {
		t.Error("SignMessage() expected error for nil key material")
	}
}

func TestFalconProvider_SignMessage_InvalidValueType(t *testing.T) {
	p := &FalconProvider{}

	keyMaterial := &signing.KeyMaterial{
		Type:  "falcon1024",
		Value: "not a KeyPair",
	}

	_, err := p.SignMessage(keyMaterial, []byte("message"))
	if err == nil {
		t.Error("SignMessage() expected error for invalid value type")
	}
}

func TestFalconProvider_ZeroKey(t *testing.T) {
	p := &FalconProvider{}

	// Generate a test key pair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, _ := falcongo.GenerateKeyPair(seed)

	keyMaterial := &signing.KeyMaterial{
		Type: "falcon1024",
		Value: &FalconKeyMaterial{
			PrivateKey: kp.PrivateKey[:],
		},
	}

	// Zero the key
	p.ZeroKey(keyMaterial)

	// Verify key material is cleared
	if keyMaterial.Type != "" {
		t.Error("ZeroKey() should clear Type")
	}
	if keyMaterial.Value != nil {
		t.Error("ZeroKey() should clear Value")
	}
}

func TestFalconProvider_ZeroKey_Nil(t *testing.T) {
	p := &FalconProvider{}

	// Should not panic
	p.ZeroKey(nil)
}

func TestFalconProvider_DetectKeyType(t *testing.T) {
	p := &FalconProvider{}

	tests := []struct {
		name       string
		keyData    []byte
		passphrase string
		want       bool
	}{
		{
			name:       "encrypted data with passphrase",
			keyData:    []byte(`{"encrypted": true}`),
			passphrase: "password",
			want:       false, // Can't detect encrypted data
		},
		{
			name:       "falcon1024 type",
			keyData:    []byte(`{"key_type": "falcon1024"}`),
			passphrase: "",
			want:       true,
		},
		{
			name:       "ed25519 type",
			keyData:    []byte(`{"key_type": "ed25519"}`),
			passphrase: "",
			want:       false,
		},
		{
			name:       "invalid json",
			keyData:    []byte(`not json`),
			passphrase: "",
			want:       false,
		},
		{
			name:       "empty key_type field errors",
			keyData:    []byte(`{"key_type": ""}`),
			passphrase: "",
			want:       false, // Empty key_type returns error from DetectKeyTypeFromData
		},
		{
			name:       "missing key_type field",
			keyData:    []byte(`{"public_key": "abc"}`),
			passphrase: "",
			want:       false, // Missing key_type returns error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.DetectKeyType(tt.keyData, tt.passphrase)
			if got != tt.want {
				t.Errorf("DetectKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFalconProviderRegistration(t *testing.T) {
	// Verify the provider is registered via init()
	provider := signing.GetProvider("falcon1024")
	if provider == nil {
		t.Fatal("Falcon signing provider not registered")
	}

	if provider.Family() != "falcon1024" {
		t.Errorf("Registered provider KeyType() = %v, want falcon1024", provider.Family())
	}
}
