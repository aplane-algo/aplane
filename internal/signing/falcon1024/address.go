// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package falcon1024 owns client-safe protocol metadata and address derivation
// for Algorand's native Falcon-1024 authorization scheme.
package falcon1024

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

const (
	KeyType             = "falcon1024"
	Scheme              = "f1"
	PublicKeySize       = 1793
	PrivateKeySize      = 2305
	MaxSignatureSize    = 1538
	RecoveryEntropySize = 32
	MnemonicWordCount   = 25
	PQFeeContribution   = uint64(2_000_000)
)

var ErrNoCanonicalSalt = errors.New("falcon1024: no canonical PQ address salt")

// Address derives the native PQ address for the exact Falcon-1024 scheme.
func Address(salt byte, publicKey []byte) (types.Address, error) {
	if len(publicKey) != PublicKeySize {
		return types.Address{}, fmt.Errorf("falcon1024 public key length %d, want %d", len(publicKey), PublicKeySize)
	}
	preimage := make([]byte, 0, len("PQA")+len(Scheme)+1+len(publicKey))
	preimage = append(preimage, "PQA"...)
	preimage = append(preimage, Scheme...)
	preimage = append(preimage, salt)
	preimage = append(preimage, publicKey...)
	digest := sha512.Sum512_256(preimage)
	return types.Address(digest), nil
}

// CanonicalAddress selects the lowest salt whose address cannot also be an
// Ed25519 public key, matching go-algorand's rejection-sampling contract.
func CanonicalAddress(publicKey []byte) (byte, types.Address, error) {
	for salt := 0; salt <= 255; salt++ {
		address, err := Address(byte(salt), publicKey)
		if err != nil {
			return 0, types.Address{}, err
		}
		if !lsigsalt.IsOnCurve(address) {
			return byte(salt), address, nil
		}
	}
	return 0, types.Address{}, ErrNoCanonicalSalt
}

// IsCompliant reports whether an address is outside the Ed25519 point set.
func IsCompliant(address types.Address) bool {
	return !lsigsalt.IsOnCurve(address)
}
