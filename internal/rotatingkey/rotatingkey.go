// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatingkey classifies rotating account key types. It is a
// Classify-axis leaf: it answers from the key-type string alone and imports no
// registry, provider, or algorithm family, so storage, scanning, and inventory
// can apply the same rules in any binary.
//
// The rotating hybrid sizes below are frozen by the key type. A test checks
// them against lsig/rotatinghybrid, the implementation that owns them.
package rotatingkey

const (
	// RotatingHybridV1 is the rotating hybrid account key type: a fixed account
	// whose authorizing Falcon-1024 plus Ed25519 stage program changes on every
	// spend.
	RotatingHybridV1 = "aplane.rotating-hybrid.v1"

	// RotatingHybridFamily is the versionless family of the rotating hybrid
	// key types, matching the naming of every other family.
	RotatingHybridFamily = "aplane.rotating-hybrid"

	// RotatingSeedSize is the stored BIP-39 seed, the only private material.
	RotatingSeedSize = 64

	// RotatingGenesisHashSize is the network binding mixed into derivation.
	RotatingGenesisHashSize = 32

	// RotatingStagePublicKeySize is one stage's Falcon-1024 public key
	// followed by its Ed25519 public key.
	RotatingStagePublicKeySize = 1793 + 32

	// RotatingMaxProgramBytes is the largest stage program: the 1870-byte
	// unsalted program plus the 3-byte off-curve salt tail.
	RotatingMaxProgramBytes = 1873

	// RotatingMaxArgumentBytes is the largest argument payload: a compressed
	// Falcon-1024 signature of at most 1423 bytes and a 64-byte Ed25519
	// signature.
	RotatingMaxArgumentBytes = 1423 + 64

	// RotatingMaxOpcodeCost is the measured cost of a salted stage program.
	RotatingMaxOpcodeCost = 3628

	// RotatingMaxValidityWindow is the longest LastValid-FirstValid span a
	// stage program accepts.
	RotatingMaxValidityWindow = 100

	// RotatingMaxLead is how far FirstValid may be ahead of the current
	// round when the signer releases a signature. The client checks the same
	// bound before asking, so an aged transaction is rebuilt instead of
	// refused.
	RotatingMaxLead = 2

	// RotatingMinRemaining is the fewest rounds that must remain before
	// LastValid when the signer releases a signature.
	RotatingMinRemaining = 10
)

// Operator-facing metadata for the rotating hybrid key type. It lives here
// because the key type has no LogicSig provider to describe it, and every
// listing (key types, the key type library, generation) must agree.
const (
	RotatingDisplayName = "Rotating hybrid (Falcon-1024 + Ed25519)"
	RotatingDescription = "Fixed account address whose authorizing Falcon-1024 and Ed25519 stage program changes on every spend. Signs only through the rotating1 flow."

	// RotatingNetworkParameter is the single creation parameter.
	RotatingNetworkParameter            = "network"
	RotatingNetworkParameterLabel       = "Network"
	RotatingNetworkParameterDescription = "Network the account is bound to: mainnet, testnet, betanet, or the network's base64 genesis hash"
	RotatingNetworkParameterExample     = "testnet"
)

// IsRotatingKeyType reports whether keyType is a rotating hybrid account.
func IsRotatingKeyType(keyType string) bool {
	switch keyType {
	case RotatingHybridV1:
		return true
	default:
		return false
	}
}

// RoutingFamily returns the family of a rotating key type. Rotating key
// types have no LogicSig provider, so family-keyed registries cannot resolve
// them through the provider registry.
func RoutingFamily(keyType string) (string, bool) {
	if IsRotatingKeyType(keyType) {
		return RotatingHybridFamily, true
	}
	return "", false
}
