// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"fmt"
	"sync"

	"github.com/algorand/falcon"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

var registerValidatorOnce sync.Once

// RegisterKeyValidator installs signer-only Falcon key-pair validation into
// the client-link-safe payload codec.
func RegisterKeyValidator() {
	registerValidatorOnce.Do(func() {
		keys.RegisterNativePQKeyPairValidator(nativefalcon.Scheme, validateKeyPair)
	})
}

func validateKeyPair(publicKey, privateKey []byte) error {
	if len(publicKey) != falcon.PublicKeySize || len(privateKey) != falcon.PrivateKeySize {
		return fmt.Errorf("invalid Falcon key sizes")
	}
	var public falcon.PublicKey
	var private falcon.PrivateKey
	copy(public[:], publicKey)
	copy(private[:], privateKey)
	defer securecrypto.ZeroBytes(private[:])

	probe := []byte("APLANE_NATIVE_FALCON1024_KEYPAIR_V1")
	signature, err := private.SignCompressed(probe)
	if err != nil {
		return fmt.Errorf("sign key-pair probe: %w", err)
	}
	defer securecrypto.ZeroBytes(signature)
	if err := public.Verify(signature, probe); err != nil {
		return fmt.Errorf("public key does not match private key: %w", err)
	}
	return nil
}
