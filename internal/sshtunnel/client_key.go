// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"
)

// clientKeyAlgorithms are the client public-key algorithms the server
// accepts, for every username. The SSH library checks this list before it
// parses the key or verifies a signature, which is the only point that stops
// an unauthenticated client before verification: a key refused later, in
// PublicKeyCallback, is still verified when the client sends a signed request
// without a preliminary query. RSA is excluded because its verification cost
// grows with a modulus size the client chooses; every algorithm here has a
// fixed key size.
var clientKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKECDSA256,
}

// clientKeyRequirement describes the accepted client keys for error messages.
const clientKeyRequirement = "Ed25519, ECDSA (P-256/384/521), or hardware-backed sk- Ed25519/ECDSA"

// CheckClientKey reports whether key is of a type the server accepts for
// client access, for a key enrolled outside the SSH flow (an operator
// import).
func CheckClientKey(key ssh.PublicKey) error {
	return checkEnrollmentKey(key)
}

// checkEnrollmentKey reports whether key may be enrolled through
// request-enrollment. clientKeyAlgorithms already refuses other keys during
// authentication; this check keeps enrollment correct if that list changes.
func checkEnrollmentKey(key ssh.PublicKey) error {
	if !slices.Contains(clientKeyAlgorithms, key.Type()) {
		return fmt.Errorf("key type %q is not accepted for client access", key.Type())
	}
	return nil
}
