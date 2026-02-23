// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"sync"
)

// AddressDeriver defines the interface for deriving addresses from public keys
type AddressDeriver interface {
	// DeriveAddress derives an Algorand address from a public key hex string
	DeriveAddress(publicKeyHex string, params map[string]string) (string, error)
}

// addressDeriverRegistry manages address derivers for different key types.
type addressDeriverRegistry struct {
	mu       sync.RWMutex
	derivers map[string]AddressDeriver
}

// Global registry instance
var addrRegistry = &addressDeriverRegistry{
	derivers: make(map[string]AddressDeriver),
}

// RegisterAddressDeriver registers an address deriver for a specific key type
func RegisterAddressDeriver(keyType string, deriver AddressDeriver) {
	addrRegistry.mu.Lock()
	defer addrRegistry.mu.Unlock()
	addrRegistry.derivers[keyType] = deriver
}

// GetAddressDeriver retrieves an address deriver by key type
func GetAddressDeriver(keyType string) (AddressDeriver, error) {
	addrRegistry.mu.RLock()
	defer addrRegistry.mu.RUnlock()
	deriver, exists := addrRegistry.derivers[keyType]
	if !exists {
		return nil, fmt.Errorf("no address deriver registered for key type: %s", keyType)
	}
	return deriver, nil
}
