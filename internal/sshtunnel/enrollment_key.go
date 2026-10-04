// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	minEnrollmentRSABits = 3072
	maxEnrollmentRSABits = 8192
)

// enrollmentKeyRequirement describes the client keys request-token accepts.
const enrollmentKeyRequirement = "Ed25519, ECDSA (P-256/384/521), hardware-backed sk- Ed25519/ECDSA, or RSA of 3072-8192 bits"

// checkEnrollmentKey reports whether key may be enrolled through
// request-token. The allowlist excludes DSA, short RSA, oversized RSA (costly
// to verify), and certificates, which product authentication does not use.
func checkEnrollmentKey(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		cryptoKey, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return fmt.Errorf("unsupported RSA key")
		}
		rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("unsupported RSA key")
		}
		if bits := rsaKey.N.BitLen(); bits < minEnrollmentRSABits || bits > maxEnrollmentRSABits {
			return fmt.Errorf("RSA key of %d bits is not accepted; need %d-%d bits", bits, minEnrollmentRSABits, maxEnrollmentRSABits)
		}
		return nil
	default:
		return fmt.Errorf("key type %q is not accepted for client access", key.Type())
	}
}
