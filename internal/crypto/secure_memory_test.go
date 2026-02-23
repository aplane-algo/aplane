// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package crypto

import (
	"bytes"
	"sync"
	"testing"
)

// TestZeroBytes_Basic verifies that byte slice is properly zeroed
func TestZeroBytes_Basic(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "single byte",
			data: []byte{0xFF},
		},
		{
			name: "multiple bytes",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name: "32 byte key",
			data: bytes.Repeat([]byte{0xAB}, 32),
		},
		{
			name: "64 byte key",
			data: bytes.Repeat([]byte{0xCD}, 64),
		},
		{
			name: "large buffer 1KB",
			data: bytes.Repeat([]byte{0xEF}, 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to verify original was non-zero
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			// Zero the data
			ZeroBytes(tt.data)

			// Verify all bytes are zero
			for i, b := range tt.data {
				if b != 0 {
					t.Errorf("byte at index %d is not zero: got %d", i, b)
				}
			}

			// Verify original was non-zero (sanity check)
			allZero := true
			for _, b := range original {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("test data should have been non-zero before zeroing")
			}
		})
	}
}

// TestZeroBytes_EmptyAndNil verifies edge cases are handled
func TestZeroBytes_EmptyAndNil(t *testing.T) {
	// Test nil slice - should not panic
	t.Run("nil slice", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ZeroBytes panicked on nil slice: %v", r)
			}
		}()
		var nilSlice []byte
		ZeroBytes(nilSlice)
	})

	// Test empty slice - should not panic
	t.Run("empty slice", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ZeroBytes panicked on empty slice: %v", r)
			}
		}()
		emptySlice := []byte{}
		ZeroBytes(emptySlice)
	})

	// Test zero-capacity slice
	t.Run("zero-capacity slice", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ZeroBytes panicked on zero-capacity slice: %v", r)
			}
		}()
		zeroCapSlice := make([]byte, 0)
		ZeroBytes(zeroCapSlice)
	})
}

// TestSecureString_Creation tests NewSecureStringFromBytes with various inputs
func TestSecureString_Creation(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectEmpty bool
	}{
		{
			name:        "valid data",
			input:       []byte("test-passphrase"),
			expectEmpty: false,
		},
		{
			name:        "nil input",
			input:       nil,
			expectEmpty: true,
		},
		{
			name:        "empty input",
			input:       []byte{},
			expectEmpty: true,
		},
		{
			name:        "binary data",
			input:       []byte{0x00, 0x01, 0xFF, 0xFE},
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := NewSecureStringFromBytes(tt.input)
			if ss == nil {
				t.Fatal("NewSecureStringFromBytes returned nil")
			}

			if ss.IsEmpty() != tt.expectEmpty {
				t.Errorf("IsEmpty() = %v, want %v", ss.IsEmpty(), tt.expectEmpty)
			}

			// Verify data was copied (if input was non-empty)
			if len(tt.input) > 0 {
				// Modify original - should not affect SecureString
				originalByte := tt.input[0]
				tt.input[0] = 0x00

				var retrievedByte byte
				err := ss.WithBytes(func(data []byte) error {
					if len(data) > 0 {
						retrievedByte = data[0]
					}
					return nil
				})
				if err != nil {
					t.Errorf("WithBytes returned error: %v", err)
				}

				if retrievedByte != originalByte {
					t.Error("SecureString data was affected by modifying original slice")
				}
			}

			// Clean up
			ss.Destroy()
		})
	}
}

// TestSecureString_WithBytes verifies callback receives correct data
func TestSecureString_WithBytes(t *testing.T) {
	testData := []byte("secret-passphrase-123")
	ss := NewSecureStringFromBytes(testData)
	defer ss.Destroy()

	// Test that callback receives correct data
	var receivedData []byte
	err := ss.WithBytes(func(data []byte) error {
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		return nil
	})

	if err != nil {
		t.Errorf("WithBytes returned error: %v", err)
	}

	if !bytes.Equal(receivedData, testData) {
		t.Errorf("WithBytes received incorrect data: got %v, want %v", receivedData, testData)
	}
}

// TestSecureString_WithBytes_Error verifies errors are propagated
func TestSecureString_WithBytes_Error(t *testing.T) {
	ss := NewSecureStringFromBytes([]byte("test"))
	defer ss.Destroy()

	expectedErr := bytes.ErrTooLarge // arbitrary error for testing
	err := ss.WithBytes(func(data []byte) error {
		return expectedErr
	})

	if err != expectedErr {
		t.Errorf("WithBytes should propagate error: got %v, want %v", err, expectedErr)
	}
}

// TestSecureString_WithBytes_NilData tests callback with nil internal data
func TestSecureString_WithBytes_NilData(t *testing.T) {
	ss := NewSecureStringFromBytes(nil)
	defer ss.Destroy()

	callbackData := []byte{0xFF} // Initialize to non-nil
	err := ss.WithBytes(func(data []byte) error {
		callbackData = data
		return nil
	})

	if err != nil {
		t.Errorf("WithBytes returned error: %v", err)
	}

	if callbackData != nil {
		t.Error("WithBytes should pass nil to callback for nil SecureString")
	}
}

// TestSecureString_Destroy verifies data is zeroed after destroy
func TestSecureString_Destroy(t *testing.T) {
	testData := []byte("secret-to-destroy")
	ss := NewSecureStringFromBytes(testData)

	// Capture data reference before destroy (for testing purposes only)
	var dataRef []byte
	_ = ss.WithBytes(func(data []byte) error {
		dataRef = data // This is unsafe in production, but needed for test
		return nil
	})

	// Destroy the secure string
	ss.Destroy()

	// Verify IsEmpty returns true
	if !ss.IsEmpty() {
		t.Error("IsEmpty() should return true after Destroy()")
	}

	// Verify the data was zeroed
	for i, b := range dataRef {
		if b != 0 {
			t.Errorf("byte at index %d not zeroed after Destroy: got %d", i, b)
		}
	}

	// Verify WithBytes now passes nil
	afterDestroyData := []byte{0xFF}
	err := ss.WithBytes(func(data []byte) error {
		afterDestroyData = data
		return nil
	})

	if err != nil {
		t.Errorf("WithBytes after Destroy returned error: %v", err)
	}

	if afterDestroyData != nil {
		t.Error("WithBytes should pass nil after Destroy")
	}
}

// TestSecureString_DoubleDestroy verifies calling Destroy twice is safe
func TestSecureString_DoubleDestroy(t *testing.T) {
	ss := NewSecureStringFromBytes([]byte("test"))

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Double Destroy caused panic: %v", r)
		}
	}()

	ss.Destroy()
	ss.Destroy() // Should not panic
}

// TestSecureString_ConcurrentAccess verifies thread safety with multiple goroutines
func TestSecureString_ConcurrentAccess(t *testing.T) {
	testData := []byte("concurrent-test-data")
	ss := NewSecureStringFromBytes(testData)
	defer ss.Destroy()

	const numGoroutines = 100
	const numIterations = 100

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numIterations)

	// Launch multiple goroutines that read concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				err := ss.WithBytes(func(data []byte) error {
					if !bytes.Equal(data, testData) {
						return bytes.ErrTooLarge // Use as a marker error
					}
					return nil
				})
				if err != nil {
					errChan <- err
				}
			}
		}()
	}

	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		t.Errorf("Concurrent read error: %v", err)
	}
}

// TestSecureString_ConcurrentReadAndDestroy verifies safety when destroy races with reads
func TestSecureString_ConcurrentReadAndDestroy(t *testing.T) {
	const numIterations = 100

	for i := 0; i < numIterations; i++ {
		ss := NewSecureStringFromBytes([]byte("test-data"))

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: Read operations
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = ss.WithBytes(func(data []byte) error {
					// Data may be nil or valid, both are acceptable
					return nil
				})
			}
		}()

		// Goroutine 2: Destroy
		go func() {
			defer wg.Done()
			ss.Destroy()
		}()

		wg.Wait()
	}
	// If we get here without panic, the test passed
}

// TestSecureString_IsEmpty verifies IsEmpty behavior
func TestSecureString_IsEmpty(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectEmpty bool
	}{
		{"nil input", nil, true},
		{"empty slice", []byte{}, true},
		{"single byte", []byte{0x01}, false},
		{"zero byte", []byte{0x00}, false}, // Contains zero byte but still has data
		{"multiple bytes", []byte("test"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := NewSecureStringFromBytes(tt.input)
			defer ss.Destroy()

			if ss.IsEmpty() != tt.expectEmpty {
				t.Errorf("IsEmpty() = %v, want %v", ss.IsEmpty(), tt.expectEmpty)
			}
		})
	}
}
