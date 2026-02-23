// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package mnemonic

import (
	"sort"
	"testing"
)

func init() {
	// Register Ed25519 handler for tests
	RegisterEd25519Handler()
}

// TestHandlerRegistry verifies the registry basics
func TestHandlerRegistry(t *testing.T) {
	// Ed25519 handler should be registered at init()
	handler, err := GetHandler("ed25519")
	if err != nil {
		t.Fatalf("Ed25519 handler should be registered: %v", err)
	}

	if handler.Family() != "ed25519" {
		t.Errorf("Expected key type 'ed25519', got '%s'", handler.Family())
	}
}

// TestGetRegisteredFamilies verifies listing registered handlers
func TestGetRegisteredFamilies(t *testing.T) {
	types := GetRegisteredFamilies()

	// Should have at least Ed25519
	if len(types) == 0 {
		t.Fatal("Expected at least one registered handler")
	}

	// Verify Ed25519 is in the list
	found := false
	for _, keyType := range types {
		if keyType == "ed25519" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Ed25519 should be in registered types")
	}

	// Verify sorting
	sortedTypes := make([]string, len(types))
	copy(sortedTypes, types)
	sort.Strings(sortedTypes)

	for i, keyType := range types {
		if keyType != sortedTypes[i] {
			t.Error("Registered types should be sorted alphabetically")
			break
		}
	}
}

// TestGetHandlerUnknownType verifies error handling for unknown key types
func TestGetHandlerUnknownType(t *testing.T) {
	_, err := GetHandler("unknown-algorithm")
	if err == nil {
		t.Fatal("Expected error for unknown key type")
	}

	expectedError := "no mnemonic handler registered for key type: unknown-algorithm"
	if err.Error() != expectedError {
		t.Errorf("Expected error %q, got %q", expectedError, err.Error())
	}
}

// TestRegisterIdempotency verifies duplicate registrations are ignored
func TestRegisterIdempotency(t *testing.T) {
	// Create a mock handler
	mockHandler := &Ed25519Handler{}

	// Get initial count
	initialTypes := GetRegisteredFamilies()
	initialCount := len(initialTypes)

	// Register same type multiple times
	Register(mockHandler)
	Register(mockHandler)
	Register(mockHandler)

	// Count should not increase
	afterTypes := GetRegisteredFamilies()
	afterCount := len(afterTypes)

	if afterCount != initialCount {
		t.Errorf("Duplicate registrations should be ignored. Initial: %d, After: %d", initialCount, afterCount)
	}
}

// MockHandler is a test handler for verification
type MockHandler struct{}

func (m *MockHandler) Family() string {
	return "mock-key-type-test"
}

func (m *MockHandler) GenerateMnemonic() (string, []byte, []byte, error) {
	return "mock words", []byte("seed"), []byte("entropy"), nil
}

func (m *MockHandler) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	return []byte("mock seed"), nil
}

func (m *MockHandler) EntropyToMnemonic(entropy []byte) (string, error) {
	return "mock mnemonic", nil
}

func (m *MockHandler) ValidateWordCount(wordCount int) error {
	return nil
}

func (m *MockHandler) WordCount() int {
	return 12
}

// TestMultipleHandlerTypes verifies multiple handlers can coexist
func TestMultipleHandlerTypes(t *testing.T) {
	// Register the mock handler
	mockHandler := &MockHandler{}
	Register(mockHandler)

	// Verify both handlers are accessible
	ed25519Handler, err := GetHandler("ed25519")
	if err != nil {
		t.Fatalf("Ed25519 handler should still be registered: %v", err)
	}

	mockRetrieved, err := GetHandler("mock-key-type-test")
	if err != nil {
		t.Fatalf("Mock handler should be registered: %v", err)
	}

	// Verify they're different types
	if ed25519Handler.Family() == mockRetrieved.Family() {
		t.Error("Handlers should have different key types")
	}
}

// TestHandlerInterface verifies the Handler interface contract
func TestHandlerInterface(t *testing.T) {
	handler, err := GetHandler("ed25519")
	if err != nil {
		t.Fatalf("Failed to get handler: %v", err)
	}

	// Verify all interface methods are callable
	t.Run("KeyType", func(t *testing.T) {
		keyType := handler.Family()
		if keyType == "" {
			t.Error("KeyType should not be empty")
		}
	})

	t.Run("WordCount", func(t *testing.T) {
		count := handler.WordCount()
		if count <= 0 {
			t.Errorf("WordCount should be positive, got %d", count)
		}
	})

	t.Run("ValidateWordCount", func(t *testing.T) {
		// Valid count should not error
		err := handler.ValidateWordCount(handler.WordCount())
		if err != nil {
			t.Errorf("ValidateWordCount with correct count should not error: %v", err)
		}

		// Invalid count should error
		err = handler.ValidateWordCount(999)
		if err == nil {
			t.Error("ValidateWordCount with wrong count should error")
		}
	})

	t.Run("GenerateMnemonic", func(t *testing.T) {
		words, seed, entropy, err := handler.GenerateMnemonic()
		if err != nil {
			t.Fatalf("GenerateMnemonic failed: %v", err)
		}

		if words == "" {
			t.Error("Generated words should not be empty")
		}

		if len(seed) == 0 {
			t.Error("Generated seed should not be empty")
		}

		// Note: entropy may be nil for some algorithms (e.g., Ed25519)
		_ = entropy
	})
}

// TestConcurrentAccess verifies thread-safe registry operations
func TestConcurrentAccess(t *testing.T) {
	const concurrency = 50

	// Launch multiple goroutines accessing the registry
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			// Read operations
			handler, err := GetHandler("ed25519")
			if err != nil {
				t.Errorf("GetHandler failed: %v", err)
			}
			if handler != nil {
				_ = handler.Family()
			}

			types := GetRegisteredFamilies()
			if len(types) == 0 {
				t.Error("Expected registered types")
			}

			// Register operations (idempotent, should be safe)
			mockHandler := &Ed25519Handler{}
			Register(mockHandler)

			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < concurrency; i++ {
		<-done
	}
}
