// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon

import (
	"context"
	"fmt"
	"testing"

	utilkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signing"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1/reference"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// testFalcon1024V1 is a minimal DSA implementation for tests.
// Implements both LogicSigDSA and LSigProvider interfaces.
type testFalcon1024V1 struct{}

// LogicSigDSA interface
func (f *testFalcon1024V1) KeyType() string          { return "aplane.falcon1024.v1" }
func (f *testFalcon1024V1) RoutingFamily() string    { return "falcon1024" }
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

func (f *testFalcon1024V1) DeriveLsig(_ context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
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
	// Uses local test implementation to avoid import cycle. Production
	// registration moved to the lsig/falcon1024/signerreg descriptor; this
	// package now only hosts the provider behavior tests.
	if logicsigdsa.Get("aplane.falcon1024.v1") == nil {
		logicsigdsa.Register(&testFalcon1024V1{})
	}
	if signing.GetProvider("falcon1024") == nil {
		signing.Register(newTestProvider())
	}
}

func newTestProvider() *signing.LogicSigProvider {
	ops := &testFalcon1024V1{}
	return signing.NewLogicSigProvider("falcon1024", map[string]signing.LogicSigSignerOps{
		"falcon1024":           ops,
		"aplane.falcon1024.v1": ops,
	})
}

func canonicalFalconPayloadForTest(keyType string, publicKey, privateKey []byte) *utilkeys.Payload {
	return utilkeys.NewDSALSigPayload(
		keyType,
		keyType,
		publicKey,
		privateKey,
		nil,
		[]byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01},
		5,
		"",
		nil,
		"",
	)
}

func canonicalFalconKeyJSONForTest(t *testing.T, keyType string, publicKey, privateKey []byte) []byte {
	t.Helper()
	data, err := utilkeys.MarshalPayload(canonicalFalconPayloadForTest(keyType, publicKey, privateKey))
	if err != nil {
		t.Fatalf("MarshalPayload(falcon test key) error = %v", err)
	}
	return data
}

func providerKeyFromFalconPayload(payload *utilkeys.Payload) signing.ProviderKey {
	return signing.ProviderKey{
		Type:                   payload.KeyType,
		Category:               payload.Category,
		BaseKeyType:            payload.BaseKeyType,
		PublicKey:              payload.PublicKey,
		PrivateKey:             payload.PrivateKey,
		SigningArgs:            utilkeys.SigningArgDefs(payload.SigningArgs),
		SigningMetadataVersion: payload.SigningMetadataVersion,
	}
}

func TestFalconProvider_Family(t *testing.T) {
	p := newTestProvider()
	if p.RoutingFamily() != "falcon1024" {
		t.Errorf("RoutingFamily() = %v, want falcon1024", p.RoutingFamily())
	}
}

func TestFalconProvider_LoadKeyMaterial_Valid(t *testing.T) {
	p := newTestProvider()

	// Generate a test key pair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	payload := canonicalFalconPayloadForTest("aplane.falcon1024.v1", kp.PublicKey[:], kp.PrivateKey[:])

	// Load keys
	keyMaterial, err := p.LoadKeyMaterial(providerKeyFromFalconPayload(payload))
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}

	if keyMaterial.Type != "aplane.falcon1024.v1" {
		t.Errorf("LoadKeyMaterial() Type = %v, want aplane.falcon1024.v1", keyMaterial.Type)
	}

	// Verify the loaded key material has private key bytes
	loadedKM, ok := keyMaterial.Value.(*signing.LsigKeyMaterial)
	if !ok {
		t.Fatal("LoadKeyMaterial() Value is not a *signing.LsigKeyMaterial")
	}

	// Verify private key was loaded (should match length of original)
	if len(loadedKM.PrivateKey) != len(kp.PrivateKey) {
		t.Errorf("LoadKeyMaterial() private key length = %d, want %d", len(loadedKM.PrivateKey), len(kp.PrivateKey))
	}
}

func TestFalconProvider_LoadKeyMaterial_InvalidInput(t *testing.T) {
	p := newTestProvider()

	_, err := p.LoadKeyMaterial(signing.ProviderKey{})
	if err == nil {
		t.Fatal("LoadKeyMaterial(zero) error = nil, want error")
	}

	_, err = p.LoadKeyMaterial(signing.ProviderKey{Type: "ed25519", Category: "ed25519"})
	if err == nil {
		t.Fatal("LoadKeyMaterial(ed25519) error = nil, want error")
	}
}

func TestFalconProvider_LoadKeyMaterial_WrongFamily(t *testing.T) {
	p := newTestProvider()
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	payload := utilkeys.NewDSALSigPayload(
		"aplane.ecdsak1.v1",
		"aplane.ecdsak1.v1",
		kp.PublicKey[:],
		kp.PrivateKey[:],
		nil,
		[]byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01},
		5,
		"",
		nil,
		"",
	)
	_, err = p.LoadKeyMaterial(providerKeyFromFalconPayload(payload))
	if err == nil {
		t.Fatal("LoadKeyMaterial(wrong family) error = nil, want error")
	}
}

func TestFalconProvider_SignMessage(t *testing.T) {
	p := newTestProvider()

	// Generate a test key pair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	keyMaterial := &signing.KeyMaterial{
		Type: "aplane.falcon1024.v1",
		Value: &signing.LsigKeyMaterial{
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
	p := newTestProvider()

	keyMaterial := &signing.KeyMaterial{
		Type:  "ed25519", // Wrong type
		Value: &signing.LsigKeyMaterial{},
	}

	_, err := p.SignMessage(keyMaterial, []byte("message"))
	if err == nil {
		t.Error("SignMessage() expected error for wrong key type")
	}
}

func TestFalconProvider_SignMessage_NilKeyMaterial(t *testing.T) {
	p := newTestProvider()

	_, err := p.SignMessage(nil, []byte("message"))
	if err == nil {
		t.Error("SignMessage() expected error for nil key material")
	}
}

func TestFalconProvider_SignMessage_InvalidValueType(t *testing.T) {
	p := newTestProvider()

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
	p := newTestProvider()

	// Generate a test key pair
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, _ := falcongo.GenerateKeyPair(seed)

	keyMaterial := &signing.KeyMaterial{
		Type: "falcon1024",
		Value: &signing.LsigKeyMaterial{
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
	p := newTestProvider()

	// Should not panic
	p.ZeroKey(nil)
}

func TestFalconProvider_DetectKeyType(t *testing.T) {
	p := newTestProvider()

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
			keyData:    canonicalFalconKeyJSONForTest(t, "falcon1024", []byte{0x01}, []byte{0x02}),
			passphrase: "",
			want:       true,
		},
		{
			name:       "ed25519 type",
			keyData:    canonicalFalconKeyJSONForTest(t, "ed25519", []byte{0x01}, []byte{0x02}),
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
			want:       false,
		},
		{
			name:       "missing key_type field",
			keyData:    []byte(`{"public_key": "abc"}`),
			passphrase: "",
			want:       false,
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

	if provider.RoutingFamily() != "falcon1024" {
		t.Errorf("Registered provider RoutingFamily() = %v, want falcon1024", provider.RoutingFamily())
	}
}
