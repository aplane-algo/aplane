// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"fmt"
	"sync"
)

// PairValidator verifies that witness private material matches its public key.
type PairValidator func(publicKey, privateKey []byte) error

var (
	pairMu         sync.RWMutex
	pairValidators = map[string]PairValidator{}
)

// RegisterPairValidator registers the validator for a witness-key type. First
// registration wins, matching the other algorithm-family registries.
func RegisterPairValidator(keyType string, validator PairValidator) {
	if validator == nil {
		return
	}
	pairMu.Lock()
	defer pairMu.Unlock()
	if _, exists := pairValidators[keyType]; exists {
		return
	}
	pairValidators[keyType] = validator
}

// ValidatePair verifies that public and private material belong together.
func ValidatePair(keyType string, publicKey, privateKey []byte) error {
	pairMu.RLock()
	validator := pairValidators[keyType]
	pairMu.RUnlock()
	if validator == nil {
		return fmt.Errorf("no pair validator registered for witness key type %s", keyType)
	}
	return validator(publicKey, privateKey)
}
