// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package verify contains pure sentry component signature verification
// helpers. It links the upstream Falcon implementation (CGo), so only
// signer-side code should import it; clients pass component signatures
// through opaquely and rely on signer assembly plus on-chain LogicSig
// enforcement. Canonical group decoding lives in internal/sentry/canonical.
package verify

import (
	"fmt"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/aplane-algo/aplane/internal/falconparams"
)

// VerifyFalcon1024 verifies a user-role Falcon-1024 component signature.
func VerifyFalcon1024(publicKey, message, signature []byte) error {
	if len(publicKey) != falcon1024PublicKeySize {
		return fmt.Errorf("falcon1024 public key length %d invalid (expected %d bytes)", len(publicKey), falcon1024PublicKeySize)
	}
	if len(signature) == 0 || len(signature) > falcon1024MaxSignatureSize {
		return fmt.Errorf("falcon1024 signature length %d invalid (expected 1..%d bytes)", len(signature), falcon1024MaxSignatureSize)
	}

	var pub falcongo.PublicKey
	copy(pub[:], publicKey)
	if err := falcongo.Verify(message, falcon.CompressedSignature(signature), pub); err != nil {
		return fmt.Errorf("falcon1024 signature verification failed: %w", err)
	}
	return nil
}

const (
	falcon1024PublicKeySize    = falconparams.PublicKeySize
	falcon1024MaxSignatureSize = falconparams.CompressedSignatureMaxSize
)
