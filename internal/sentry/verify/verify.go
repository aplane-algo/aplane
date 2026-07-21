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

// Falcon-1024 sizes are fixed by the algorithm specification; they are
// declared as literals so this package's only falcon dependencies are the
// upstream implementation libraries, not the aplane lsig family tree
// (verify_consistency_test.go cross-checks them against
// lsig/falcon1024/family).
const (
	falcon1024PublicKeySize    = 1793
	falcon1024MaxSignatureSize = 1280
)
