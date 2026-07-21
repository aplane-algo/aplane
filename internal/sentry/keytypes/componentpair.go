// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes

import (
	"fmt"
	"sync"
)

// ComponentPairValidator verifies that a sentry component private key
// matches its public key.
type ComponentPairValidator func(publicKey, privateKey []byte) error

var (
	componentPairMu         sync.RWMutex
	componentPairValidators = map[string]ComponentPairValidator{}
)

// RegisterComponentPairValidator registers the public/private pair validator
// for a sentry component key type. Algorithm families register their
// validator alongside their other signer-side registrations so core key
// plumbing never imports a family package. First registration wins;
// duplicates are ignored, matching the other family registries.
func RegisterComponentPairValidator(keyType string, v ComponentPairValidator) {
	if v == nil {
		return
	}
	componentPairMu.Lock()
	defer componentPairMu.Unlock()
	if _, exists := componentPairValidators[keyType]; exists {
		return
	}
	componentPairValidators[keyType] = v
}

// ValidateComponentPair verifies that a sentry component public/private pair
// belongs together. Every family must have registered a validator, and
// validation fails closed when none is registered.
func ValidateComponentPair(keyType string, publicKey, privateKey []byte) error {
	componentPairMu.RLock()
	validator := componentPairValidators[keyType]
	componentPairMu.RUnlock()
	if validator == nil {
		return fmt.Errorf("no component pair validator registered for sentry key type %s", keyType)
	}
	return validator(publicKey, privateKey)
}
