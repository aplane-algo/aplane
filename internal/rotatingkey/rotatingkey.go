// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatingkey classifies rotating account key types. It is a
// Classify-axis leaf: it answers from the key-type string alone and imports no
// registry, provider, or algorithm family, so storage, scanning, and inventory
// can apply the same rules in any binary.
//
// The sizes below are frozen by the key type. Tests check them against
// lsig/rotatingtriple, the implementation that owns them.
package rotatingkey

const (
	// RotatingTripleWotsV1 is the rotating account key type: a fixed
	// account whose authorizing stage program changes on every spend, and
	// whose every stage requires a Falcon-1024, a WOTS-w16 (SHA-256) and an
	// Ed25519 signature.
	RotatingTripleWotsV1 = "aplane.rotating-triple-wots.v1"

	// RotatingTripleXmssV1 is the rotating account key type whose hash-based
	// signature is RFC 8391 XMSS: one XMSS tree serves 1,024 consecutive
	// stages and each stage signs with its own 64 leaves, beside a
	// Falcon-1024 and an Ed25519 key per stage.
	RotatingTripleXmssV1 = "aplane.rotating-triple-xmss.v1"

	// RotatingTripleXmssFamily is the versionless family of the XMSS triple.
	RotatingTripleXmssFamily = "aplane.rotating-triple-xmss"

	// RotatingTripleWotsFamily is the versionless family of the WOTS triple,
	// matching the naming of every other family.
	RotatingTripleWotsFamily = "aplane.rotating-triple-wots"

	// RotatingSeedSize is the stored BIP-39 seed, the only private material.
	RotatingSeedSize = 64

	// RotatingGenesisHashSize is the network binding mixed into derivation.
	RotatingGenesisHashSize = 32

	// RotatingTripleStagePublicKeySize is the triple hybrid's stage 0 record:
	// the stage 0 tweak (which carries the public account tag), the
	// Falcon-1024 public key, the WOTS public key and the Ed25519 public key.
	RotatingTripleStagePublicKeySize = 32 + 1793 + 32 + 32

	// RotatingTripleMaxProgramBytes is the salted triple stage program.
	RotatingTripleMaxProgramBytes = 2103

	// RotatingTripleMaxArgumentBytes is a 2,144-byte WOTS signature, a
	// 64-byte Ed25519 signature and a compressed Falcon-1024 signature of at
	// most 1,423 bytes.
	RotatingTripleMaxArgumentBytes = 2144 + 64 + 1423

	// RotatingTripleMaxOpcodeCost is the worst accepting run of a salted
	// triple stage program: 7,296 plus 53 per chain step over at most 990
	// steps.
	RotatingTripleMaxOpcodeCost = 7301 + 53*990 + 1

	// RotatingXmssStagePublicKeySize is the XMSS triple's stage 0 record: the
	// public account tag, the Falcon-1024 public key, tree 0's root and public
	// seed, and the Ed25519 public key.
	RotatingXmssStagePublicKeySize = 32 + 1793 + 32 + 32 + 32

	// RotatingXmssMaxProgramBytes is the salted XMSS stage program.
	RotatingXmssMaxProgramBytes = 2664

	// RotatingXmssMaxArgumentBytes is a 2,692-byte XMSS signature, a 64-byte
	// Ed25519 signature and a Falcon-1024 signature of at most 1,423 bytes.
	RotatingXmssMaxArgumentBytes = 2692 + 64 + 1423

	// RotatingXmssMaxOpcodeCost is the worst accepting run of an XMSS stage
	// program: 25,507 plus 134 per chain step over at most 525 steps, the
	// most a signature within the stage's checksum cap of 511 can need.
	RotatingXmssMaxOpcodeCost = 25507 + 134*525

	// RotatingXmssLeavesPerStage and RotatingXmssStagesPerTree describe the
	// XMSS triple's leaf allocation: a tree of 65,536 leaves split into
	// 1,024 stages of 64.
	RotatingXmssLeavesPerStage = 64
	RotatingXmssStagesPerTree  = 65536 / RotatingXmssLeavesPerStage

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

// Operator-facing metadata for the rotating key type. It lives here because
// the key type has no LogicSig provider to describe it, and every listing
// (key types, the key type library, generation) must agree.
const (
	RotatingTripleDisplayName = "Rotating triple WOTS (Falcon-1024 + WOTS + Ed25519)"
	RotatingTripleDescription = "Fixed account address whose authorizing Falcon-1024, hash-based WOTS and Ed25519 stage program changes on every spend. Signs only through the rotating1 flow."

	RotatingTripleXmssDisplayName = "Rotating triple XMSS (Falcon-1024 + XMSS + Ed25519)"
	RotatingTripleXmssDescription = "Fixed account address whose authorizing Falcon-1024, RFC 8391 XMSS and Ed25519 stage program changes on every spend. One XMSS tree serves 1,024 stages, each signing with its own 64 leaves. Signs only through the rotating1 flow."

	// RotatingNetworkParameter is the single creation parameter.
	RotatingNetworkParameter            = "network"
	RotatingNetworkParameterLabel       = "Network"
	RotatingNetworkParameterDescription = "Network the account is bound to: mainnet, testnet, betanet, or the network's base64 genesis hash"
	RotatingNetworkParameterExample     = "testnet"
)

// Profile is what storage, inventory and the signing flow need to know
// about a rotating key type without linking its implementation. One entry
// today; the map stays because the classification is by key type, not by
// "is rotating", and the rotating-bounded contract will add entries.
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

	// LeavesPerStage is how many one-time leaves a stage holds, 1 for a
	// family with one key per stage. StagesPerTree is how many consecutive
	// stages share one tree, 0 when every stage is its own tree. Together
	// they place a stage's leaf range: stage n's leaves are
	// (n mod StagesPerTree) * LeavesPerStage onward.
	LeavesPerStage int
	StagesPerTree  int
}

// LeafRange returns the leaf indices stage n may sign with, lo <= leaf < hi.
func (p Profile) LeafRange(stage uint64) (lo, hi uint64) {
	if p.LeavesPerStage <= 1 || p.StagesPerTree <= 0 {
		return 0, 1
	}
	lo = (stage % uint64(p.StagesPerTree)) * uint64(p.LeavesPerStage)
	return lo, lo + uint64(p.LeavesPerStage)
}

// TreeOf returns the tree a stage belongs to, 0 for a family without
// shared trees.
func (p Profile) TreeOf(stage uint64) uint64 {
	if p.StagesPerTree <= 0 {
		return 0
	}
	return stage / uint64(p.StagesPerTree)
}

var profiles = map[string]Profile{
	RotatingTripleWotsV1: {
		KeyType:            RotatingTripleWotsV1,
		Family:             RotatingTripleWotsFamily,
		DisplayName:        RotatingTripleDisplayName,
		Description:        RotatingTripleDescription,
		StagePublicKeySize: RotatingTripleStagePublicKeySize,
		MaxProgramBytes:    RotatingTripleMaxProgramBytes,
		MaxArgumentBytes:   RotatingTripleMaxArgumentBytes,
		MaxOpcodeCost:      RotatingTripleMaxOpcodeCost,
		OneTimeStage:       true,
		ReusedStageRestsOn: "Falcon-1024 and Ed25519",
		LeavesPerStage:     1,
	},
	RotatingTripleXmssV1: {
		KeyType:            RotatingTripleXmssV1,
		Family:             RotatingTripleXmssFamily,
		DisplayName:        RotatingTripleXmssDisplayName,
		Description:        RotatingTripleXmssDescription,
		StagePublicKeySize: RotatingXmssStagePublicKeySize,
		MaxProgramBytes:    RotatingXmssMaxProgramBytes,
		MaxArgumentBytes:   RotatingXmssMaxArgumentBytes,
		MaxOpcodeCost:      RotatingXmssMaxOpcodeCost,
		OneTimeStage:       true,
		ReusedStageRestsOn: "Falcon-1024 and Ed25519",
		LeavesPerStage:     RotatingXmssLeavesPerStage,
		StagesPerTree:      RotatingXmssStagesPerTree,
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
	return []string{RotatingTripleWotsV1, RotatingTripleXmssV1}
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
