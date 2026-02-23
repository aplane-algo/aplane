// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package reference contains the vendored LogicSig derivation code from
// github.com/algorandfoundation/falcon-signatures v1.1.1
//
// This code is frozen to ensure address stability. If the upstream library
// changes its TEAL template, addresses derived from the same public key would
// change, breaking mnemonic-only recovery.
//
// DO NOT MODIFY this code unless you are adding a new version (v2, v3, etc.)
package reference

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// ErrInvalidFalconPublicKey is returned when no suitable counter value can be found
// to derive an address that is not a valid ed25519 public key.
var ErrInvalidFalconPublicKey = errors.New(
	"unsuitable Falcon public key for Algorand address")

// DerivePQLogicSig returns a LogicSig that verifies a Falcon signature.
// The LogicSig embeds the Falcon public key and verifies the matching private key
// was used to sign the transaction ID.
//
// This is the v1 derivation, frozen from falcon-signatures v1.1.1.
// The bytecode structure is:
//
//	offset	|	bytes			| teal
//	_______________________________________________________________________
//	      0	|	0c				| #pragma version 12
//	      1	|	26 01 01 00		| bytecblock 0x00
//	      5	|	31 17			| txn TxID
//	      7	|	2d				| arg 0
//	      8	|	80 81 0e 00... 	| pushbytes 0x00... (1793 public key bytes)
//	   1804	|	85				| falcon_verify
func DerivePQLogicSig(publicKey falcongo.PublicKey) (crypto.LogicSigAccount, error) {
	maxIterations := 256
	for counter := range maxIterations {
		lsig := crypto.LogicSigAccount{
			Lsig: types.LogicSig{
				Logic: patchPrecompiledPQlogicsig(publicKey, byte(counter)),
			},
		}
		lsa, err := lsig.Address()
		if err != nil {
			return crypto.LogicSigAccount{}, err
		}
		if !isOnTheCurve(lsa[:]) {
			return lsig, nil
		}
	}
	return crypto.LogicSigAccount{}, ErrInvalidFalconPublicKey
}

// patchPrecompiledPQlogicsig returns the compiled PQlogicsig TEAL code
// with the given Falcon public key and counter value.
func patchPrecompiledPQlogicsig(publicKey falcongo.PublicKey, counter byte) []byte {
	// TEAL v12 bytecode template:
	// 0x0c          = #pragma version 12
	// 0x26 01 01 00 = bytecblock with counter (byte at offset 4)
	// 0x31 0x17     = txn TxID
	// 0x2d          = arg 0
	// 0x80 0x81 0x0e = pushbytes followed by varint 1793 (0x81 0x0e)
	// ... 1793 bytes of public key ...
	// 0x85          = falcon_verify
	precompiled := []byte{
		0x0c,
		0x26, 0x01, 0x01, 0x00,
		0x31, 0x17,
		0x2d,
		0x80, 0x81, 0x0e,
	}
	precompiled[4] = counter
	precompiled = append(precompiled, publicKey[:]...)
	precompiled = append(precompiled, 0x85)
	return precompiled
}

// isOnTheCurve returns true if the 32-byte value decodes to a valid edwards25519
// curve point (i.e., could be an ed25519 public key), and false otherwise.
// We need to avoid addresses that look like ed25519 public keys.
func isOnTheCurve(address []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(address)
	return err == nil
}
