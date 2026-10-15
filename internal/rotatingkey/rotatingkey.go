// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatingkey classifies rotating account key types. It is a
// Classify-axis leaf: it answers from the key-type string alone and imports no
// registry, provider, or algorithm family, so storage, scanning, and inventory
// can apply the same rules in any binary.
//
// The sizes below are frozen by each key type. Tests check them against
// lsig/rotatinghybrid and lsig/rotatingwots, the implementations that own
// them.
package rotatingkey

const (
	// RotatingHybridV1 is the rotating hybrid account key type: a fixed account
	// whose authorizing Falcon-1024 plus Ed25519 stage program changes on every
	// spend.
	RotatingHybridV1 = "aplane.rotating-hybrid.v1"

	// RotatingHybridFamily is the versionless family of the rotating hybrid
	// key types, matching the naming of every other family.
	RotatingHybridFamily = "aplane.rotating-hybrid"

	// RotatingWotsHybridV1 is the hash-based rotating account key type: the
	// same rotation with a WOTS-w16 (SHA-256) plus Ed25519 stage program.
	RotatingWotsHybridV1 = "aplane.rotating-wots-hybrid.v1"

	// RotatingWotsHybridFamily is its versionless family.
	RotatingWotsHybridFamily = "aplane.rotating-wots-hybrid"

	// RotatingTripleHybridV1 is the rotating account whose every stage
	// requires a Falcon-1024, a WOTS-w16 (SHA-256) and an Ed25519 signature.
	RotatingTripleHybridV1 = "aplane.rotating-triple-hybrid.v1"

	// RotatingTripleHybridFamily is its versionless family.
	RotatingTripleHybridFamily = "aplane.rotating-triple-hybrid"

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

	// RotatingWotsStagePublicKeySize is the WOTS hybrid's stage 0 record: the
	// public account tag, the WOTS public key and the Ed25519 public key.
	RotatingWotsStagePublicKeySize = 32 + 32 + 32

	// RotatingWotsMaxProgramBytes is the salted WOTS stage program.
	RotatingWotsMaxProgramBytes = 295

	// RotatingWotsMaxArgumentBytes is a 2,144-byte WOTS signature and a
	// 64-byte Ed25519 signature.
	RotatingWotsMaxArgumentBytes = 2144 + 64

	// RotatingWotsMaxOpcodeCost is the worst accepting run of a salted WOTS
	// stage program: 5,592 plus 53 per chain step over at most 990 steps.
	RotatingWotsMaxOpcodeCost = 5592 + 53*990 + 1

	// RotatingTripleStagePublicKeySize is the triple hybrid's stage 0 record:
	// the stage 0 tweak (which carries the public account tag), the
	// Falcon-1024 public key, the WOTS public key and the Ed25519 public key.
	RotatingTripleStagePublicKeySize = 32 + 1793 + 32 + 32

	// RotatingTripleMaxProgramBytes is the salted triple stage program.
	RotatingTripleMaxProgramBytes = 2096

	// RotatingTripleMaxArgumentBytes is a 2,144-byte WOTS signature, a
	// 64-byte Ed25519 signature and a compressed Falcon-1024 signature of at
	// most 1,423 bytes.
	RotatingTripleMaxArgumentBytes = 2144 + 64 + 1423

	// RotatingTripleMaxOpcodeCost is the worst accepting run of a salted
	// triple stage program: 7,296 plus 53 per chain step over at most 990
	// steps.
	RotatingTripleMaxOpcodeCost = 7296 + 53*990 + 1

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

// Operator-facing metadata for the rotating key types. It lives here
// because the key types have no LogicSig provider to describe them, and
// every listing (key types, the key type library, generation) must agree.
const (
	RotatingDisplayName = "Rotating hybrid (Falcon-1024 + Ed25519)"
	RotatingDescription = "Fixed account address whose authorizing Falcon-1024 and Ed25519 stage program changes on every spend. Signs only through the rotating1 flow."

	RotatingWotsDisplayName = "Rotating hash hybrid (WOTS + Ed25519)"
	RotatingWotsDescription = "Fixed account address whose authorizing hash-based WOTS and Ed25519 stage program changes on every spend. Signs only through the rotating1 flow."

	RotatingTripleDisplayName = "Rotating triple hybrid (Falcon-1024 + WOTS + Ed25519)"
	RotatingTripleDescription = "Fixed account address whose authorizing Falcon-1024, hash-based WOTS and Ed25519 stage program changes on every spend. Signs only through the rotating1 flow."

	// RotatingNetworkParameter is the single creation parameter.
	RotatingNetworkParameter            = "network"
	RotatingNetworkParameterLabel       = "Network"
	RotatingNetworkParameterDescription = "Network the account is bound to: mainnet, testnet, betanet, or the network's base64 genesis hash"
	RotatingNetworkParameterExample     = "testnet"
)

// Profile is what storage, inventory and the signing flow need to know
// about a rotating key type without linking its implementation.
type Profile struct {
	KeyType     string
	Family      string
	DisplayName string
	Description string

	// StagePublicKeySize is the size of the key file's stage 0 public record.
	StagePublicKeySize int

	// MaxProgramBytes, MaxArgumentBytes and MaxOpcodeCost bound every stage
	// program and every spend's LogicSig arguments.
	MaxProgramBytes  int
	MaxArgumentBytes int
	MaxOpcodeCost    int

	// OneTimeStage reports that a stage includes a one-time signature
	// scheme: a stage that signs two different messages loses that scheme's
	// protection until the account moves past it. The signer still signs
	// (the flow is stateless by design) but reports the reuse.
	OneTimeStage bool

	// ReusedStageRestsOn names what a reused one-time stage still rests on,
	// for the reuse warning.
	ReusedStageRestsOn string
}

var profiles = map[string]Profile{
	RotatingHybridV1: {
		KeyType:            RotatingHybridV1,
		Family:             RotatingHybridFamily,
		DisplayName:        RotatingDisplayName,
		Description:        RotatingDescription,
		StagePublicKeySize: RotatingStagePublicKeySize,
		MaxProgramBytes:    RotatingMaxProgramBytes,
		MaxArgumentBytes:   RotatingMaxArgumentBytes,
		MaxOpcodeCost:      RotatingMaxOpcodeCost,
	},
	RotatingWotsHybridV1: {
		KeyType:            RotatingWotsHybridV1,
		Family:             RotatingWotsHybridFamily,
		DisplayName:        RotatingWotsDisplayName,
		Description:        RotatingWotsDescription,
		StagePublicKeySize: RotatingWotsStagePublicKeySize,
		MaxProgramBytes:    RotatingWotsMaxProgramBytes,
		MaxArgumentBytes:   RotatingWotsMaxArgumentBytes,
		MaxOpcodeCost:      RotatingWotsMaxOpcodeCost,
		OneTimeStage:       true,
		ReusedStageRestsOn: "Ed25519 only",
	},
	RotatingTripleHybridV1: {
		KeyType:            RotatingTripleHybridV1,
		Family:             RotatingTripleHybridFamily,
		DisplayName:        RotatingTripleDisplayName,
		Description:        RotatingTripleDescription,
		StagePublicKeySize: RotatingTripleStagePublicKeySize,
		MaxProgramBytes:    RotatingTripleMaxProgramBytes,
		MaxArgumentBytes:   RotatingTripleMaxArgumentBytes,
		MaxOpcodeCost:      RotatingTripleMaxOpcodeCost,
		OneTimeStage:       true,
		ReusedStageRestsOn: "Falcon-1024 and Ed25519",
	},
}

// IsRotatingKeyType reports whether keyType is a rotating account.
func IsRotatingKeyType(keyType string) bool {
	_, ok := profiles[keyType]
	return ok
}

// Lookup returns a rotating key type's profile.
func Lookup(keyType string) (Profile, bool) {
	p, ok := profiles[keyType]
	return p, ok
}

// KeyTypes lists the rotating key types in a fixed order.
func KeyTypes() []string {
	return []string{RotatingHybridV1, RotatingWotsHybridV1, RotatingTripleHybridV1}
}

// RoutingFamily returns the family of a rotating key type. Rotating key
// types have no LogicSig provider, so family-keyed registries cannot resolve
// them through the provider registry.
func RoutingFamily(keyType string) (string, bool) {
	p, ok := profiles[keyType]
	if !ok {
		return "", false
	}
	return p.Family, true
}
