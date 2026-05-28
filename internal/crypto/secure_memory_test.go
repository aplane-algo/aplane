// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
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
