// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package addressderive derives on-chain addresses from signer public keys.
package addressderive

import (
	"fmt"
	"sync"
)

// Deriver defines the interface for deriving addresses from public keys.
type Deriver interface {
	DeriveAddress(publicKeyHex string, params map[string]string) (string, error)
}

type registry struct {
	mu       sync.RWMutex
	derivers map[string]Deriver
}

var globalRegistry = &registry{
	derivers: make(map[string]Deriver),
}

// Register registers an address deriver for a process-global key type name.
// Identity-private provider namespaces are not supported. Existing keys are
// isolated by product keystore; generation and inventory are gated by
// product-store activation and template install state before derivation.
func Register(keyType string, deriver Deriver) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.derivers[keyType] = deriver
}

// Get retrieves an address deriver by key type.
func Get(keyType string) (Deriver, error) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	deriver, exists := globalRegistry.derivers[keyType]
	if !exists {
		return nil, fmt.Errorf("no address deriver registered for key type: %s", keyType)
	}
	return deriver, nil
}
