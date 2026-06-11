// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes

import (
	"bytes"
	"crypto/ed25519"
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
// belongs together. Ed25519 is validated built-in (stdlib only); every other
// family must have registered a validator, and validation fails closed when
// none is registered.
func ValidateComponentPair(keyType string, publicKey, privateKey []byte) error {
	if keyType == SentryComponentEd25519V1 {
		if len(privateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("sentry private key length %d invalid (expected %d bytes)", len(privateKey), ed25519.PrivateKeySize)
		}
		derivedPublicKey, ok := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
		if !ok || !bytes.Equal(derivedPublicKey, publicKey) {
			return fmt.Errorf("sentry public key does not match private key")
		}
		return nil
	}

	componentPairMu.RLock()
	validator := componentPairValidators[keyType]
	componentPairMu.RUnlock()
	if validator == nil {
		return fmt.Errorf("no component pair validator registered for sentry key type %s", keyType)
	}
	return validator(publicKey, privateKey)
}
