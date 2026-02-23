// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/signing/ed25519"
	falconsigning "github.com/aplane-algo/aplane/lsig/falcon1024/signing"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
)

func init() {
	// Register providers explicitly instead of using blank imports
	v1.RegisterLogicSigDSA() // Must be called first - falcon signing depends on logicsigdsa.Get()
	ed25519.RegisterProvider()
	falconsigning.RegisterProvider()
}

// MockProvider for testing
type MockProvider struct {
	keyType string
}

func (m *MockProvider) Family() string {
	return m.keyType
}

func (m *MockProvider) LoadKeysFromData(data []byte) (*signing.KeyMaterial, error) {
	return &signing.KeyMaterial{
		Type:  m.keyType,
		Value: "mock-key",
	}, nil
}

func (m *MockProvider) SignMessage(key *signing.KeyMaterial, message []byte) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func (m *MockProvider) ZeroKey(key *signing.KeyMaterial) {
	// No-op for mock
}

func (m *MockProvider) DetectKeyType(keyData []byte, passphrase string) bool {
	return true
}

func TestRegistry(t *testing.T) {
	// Create a mock provider for testing
	mockProvider := &MockProvider{keyType: "test-algo"}

	// Register it
	signing.Register(mockProvider)

	// Test retrieval
	retrieved := signing.GetProvider("test-algo")
	if retrieved == nil {
		t.Fatal("Failed to retrieve registered provider")
	}

	if retrieved.Family() != "test-algo" {
		t.Errorf("Expected key type 'test-algo', got %s", retrieved.Family())
	}

	// Test signing
	testKey := &signing.KeyMaterial{
		Type:  "test-algo",
		Value: "test-key",
	}
	sig, err := retrieved.SignMessage(testKey, []byte("test-message"))
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if string(sig) != "mock-signature" {
		t.Errorf("Expected 'mock-signature', got %s", string(sig))
	}
}

func TestProviderAutoRegistration(t *testing.T) {
	// Test that Falcon provider is auto-registered
	falconProvider := signing.GetProvider("falcon1024")
	if falconProvider == nil {
		t.Error("Falcon provider not auto-registered")
	}

	// Test that Ed25519 provider is auto-registered
	ed25519Provider := signing.GetProvider("ed25519")
	if ed25519Provider == nil {
		t.Error("Ed25519 provider not auto-registered")
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	family := "duplicate-panic-test"
	provider := &MockProvider{keyType: family}

	signing.Register(provider)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()

	signing.Register(provider) // should panic
}
