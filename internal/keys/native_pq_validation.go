// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"fmt"
	"sync"
)

// NativePQKeyPairValidator performs signer-owned private-key validation
// without linking the Falcon implementation into client-safe storage code.
type NativePQKeyPairValidator func(publicKey, privateKey []byte) error

var nativePQValidators = struct {
	sync.RWMutex
	byScheme map[string]NativePQKeyPairValidator
}{byScheme: make(map[string]NativePQKeyPairValidator)}

// RegisterNativePQKeyPairValidator registers one validator for a closed PQ
// scheme. Duplicate registration is a programming error.
func RegisterNativePQKeyPairValidator(scheme string, validator NativePQKeyPairValidator) {
	if scheme == "" || validator == nil {
		panic("native PQ key-pair validator requires scheme and implementation")
	}
	nativePQValidators.Lock()
	defer nativePQValidators.Unlock()
	if _, exists := nativePQValidators.byScheme[scheme]; exists {
		panic("duplicate native PQ key-pair validator for scheme: " + scheme)
	}
	nativePQValidators.byScheme[scheme] = validator
}

func validateNativePQKeyPair(scheme string, publicKey, privateKey []byte) error {
	nativePQValidators.RLock()
	validator := nativePQValidators.byScheme[scheme]
	nativePQValidators.RUnlock()
	if validator == nil {
		return fmt.Errorf("native PQ scheme %q is not registered in this signer", scheme)
	}
	return validator(publicKey, privateKey)
}
