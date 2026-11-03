// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/sha512"
	"fmt"

	"github.com/algorand/falcon"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// DeriveKeyPair reconstructs the protocol-native Falcon key pair from its
// 32-byte recovery entropy: the working seed is
// SHA512/256("PQK" || scheme || entropy). The caller owns and must zero the
// returned private key.
func DeriveKeyPair(entropy []byte) (falcon.PublicKey, falcon.PrivateKey, error) {
	if len(entropy) != nativefalcon.RecoveryEntropySize {
		return falcon.PublicKey{}, falcon.PrivateKey{}, fmt.Errorf("native Falcon requires %d-byte recovery entropy, got %d", nativefalcon.RecoveryEntropySize, len(entropy))
	}
	seedInput := make([]byte, 0, len("PQK")+len(nativefalcon.Scheme)+len(entropy))
	seedInput = append(seedInput, "PQK"...)
	seedInput = append(seedInput, nativefalcon.Scheme...)
	seedInput = append(seedInput, entropy...)
	workingSeed := sha512.Sum512_256(seedInput)
	securecrypto.ZeroBytes(seedInput)
	defer securecrypto.ZeroBytes(workingSeed[:])

	return falcon.GenerateKey(workingSeed[:])
}
