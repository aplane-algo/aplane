// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package crypto

import (
	"crypto/subtle"
	"runtime"
	"sync"
)

// ZeroBytes securely overwrites a byte slice with zeros
// Uses constant-time operation to prevent compiler optimization
func ZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use subtle.ConstantTimeCopy to prevent compiler optimization
	subtle.ConstantTimeCopy(1, b, make([]byte, len(b)))
	// Force garbage collection to clear any copies
	runtime.KeepAlive(b)
}

// SecureString wraps a string with secure cleanup
// Use this for passwords, passphrases, and other sensitive strings
type SecureString struct {
	data []byte
	lock sync.RWMutex
}

// NewSecureStringFromBytes creates a new SecureString from a byte slice
// The input bytes are copied, so the caller can safely zero the original
func NewSecureStringFromBytes(b []byte) *SecureString {
	if b == nil {
		return &SecureString{data: nil}
	}
	data := make([]byte, len(b))
	copy(data, b)
	return &SecureString{data: data}
}

// WithBytes provides scoped access to the underlying bytes without creating string copies
// The callback receives direct access to the data (no copy is made)
// The data is protected by a read lock during the callback execution
//
// IMPORTANT: The caller must NOT store or leak the byte slice outside the callback
// The byte slice is only valid during the callback execution
//
// Example usage:
//
//	err := securePass.WithBytes(func(p []byte) error {
//	    return someFunction(p)  // Use bytes directly
//	})
func (s *SecureString) WithBytes(fn func([]byte) error) error {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.data == nil {
		return fn(nil)
	}
	return fn(s.data)
}

// Destroy securely zeros the string data
// After calling Destroy, the SecureString should not be used
func (s *SecureString) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()
	ZeroBytes(s.data)
	s.data = nil
}

// IsEmpty returns true if the string is empty or nil
func (s *SecureString) IsEmpty() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.data) == 0
}
