// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatingkey classifies rotating account key types. It is a
// Classify-axis leaf: it answers from the key-type string alone and imports no
// registry, provider, or algorithm family, so storage, scanning, and inventory
// can apply the same rules in any binary.
//
// The sizes below are frozen by the key type at its first release. Tests check
// them against each family's stage package, which owns them.
package rotatingkey

const (
	// RotatingSlhdsaHeight is the SLH-DSA hypertree height the rotating
	// SLH-DSA key type is built with: the one build-time choice of that type.
	// lsig/rotatingtripleslhdsa/stage carries a frozen verifier, template,
	// argument layout and cost model for each supported value and the
	// literals below follow it; changing the constant and rebuilding selects
	// them all. Every stage address, and so every account address, follows
	// from it: a key generated under one height is a different account
	// under the other. Supported values:
	//
	//   - 22: two layers of height 11, a 4,400-byte signature and a
	//     six-transaction group. Not a FIPS 205 parameter set.
	//   - 63: seven layers of height 9, SLH-DSA-SHA2-128s of FIPS 205, a
	//     7,856-byte signature and a ten-transaction group.
	RotatingSlhdsaHeight = 22

	// RotatingTripleSlhdsaV1 uses a stateless SLH-DSA key per stage under the
	// SLH-DSA-SHA2-128s construction at RotatingSlhdsaHeight.
	// lsig/rotatingtripleslhdsa owns the implementation.
	RotatingTripleSlhdsaV1           = "aplane.rotating-triple-slhdsa.v1"
	RotatingTripleSlhdsaFamily       = "aplane.rotating-triple-slhdsa"
	RotatingSlhdsaStagePublicKeySize = 16 + 16 + 1793 + 32
	RotatingTripleSlhdsaDisplayName  = "Rotating triple SLH-DSA (Falcon-1024 + SLH-DSA + Ed25519)"
)

// The SLH-DSA literals the selected hypertree height fixes: the salted
// stage program, the largest LogicSig arguments and the worst accepting
// opcode cost. Tests pin them to lsig/rotatingtripleslhdsa/stage.
var (
	RotatingSlhdsaMaxProgramBytes   = slhdsaShape.programBytes
	RotatingSlhdsaMaxArgumentBytes  = slhdsaShape.argumentBytes
	RotatingSlhdsaMaxOpcodeCost     = slhdsaShape.opcodeCost
	RotatingTripleSlhdsaDescription = "Fixed account address with fresh Falcon-1024, " + slhdsaShape.scheme + " and Ed25519 authority per spend. No one-time leaf tracking. Signs only through rotating1."
)

var slhdsaShape = map[int]struct {
	programBytes, argumentBytes, opcodeCost int
	scheme                                  string
}{
	22: {2837, 4400 + 64 + 1423, 26825 + 41*1020, "two-layer SLH-DSA-SHA2-128 (not a FIPS 205 parameter set)"},
	63: {2866, 7856 + 64 + 1423, 40888 + 41*3570, "SLH-DSA-SHA2-128s"},
}[RotatingSlhdsaHeight]

const (
	// RotatingTripleXmssV1 is the rotating account key type whose hash-based
	// signature is RFC 8391 XMSS: one XMSS tree serves 1,024 consecutive
	// stages and each stage signs with its own 64 leaves, beside a
	// Falcon-1024 and an Ed25519 key per stage.
	RotatingTripleXmssV1 = "aplane.rotating-triple-xmss.v1"

	// RotatingTripleXmssFamily is the versionless family of the XMSS triple.
	RotatingTripleXmssFamily = "aplane.rotating-triple-xmss"

	// RotatingTripleWotscV1 is the rotating account key type whose hash-based
	// signature comes from a tree of 64 WOTS+C keys, built per stage, beside a
	// Falcon-1024 and an Ed25519 key per stage.
	RotatingTripleWotscV1 = "aplane.rotating-triple-wotsc.v1"

	// RotatingTripleWotscFamily is the versionless family of the WOTS+C triple.
	RotatingTripleWotscFamily = "aplane.rotating-triple-wotsc"

	// RotatingSeedSize is the stored BIP-39 seed, the only private material.
	RotatingSeedSize = 64

	// RotatingGenesisHashSize is the network binding mixed into derivation.
	RotatingGenesisHashSize = 32

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

	// RotatingWotscStagePublicKeySize is the WOTS+C triple's stage 0 record:
	// public seed, root, Falcon-1024 key, Ed25519 key. Each stage is its own
	// tree, so unlike XMSS it needs no account tag.
	RotatingWotscStagePublicKeySize = 16 + 16 + 1793 + 32

	// RotatingWotscMaxProgramBytes is the salted WOTS+C stage program.
	RotatingWotscMaxProgramBytes = 2486

	// RotatingWotscMaxArgumentBytes is a 628-byte WOTS+C signature, a 64-byte
	// Ed25519 signature and a Falcon-1024 signature of at most 1,423 bytes.
	RotatingWotscMaxArgumentBytes = 628 + 64 + 1423

	// RotatingWotscMaxOpcodeCost is the exact cost of every accepted run: the
	// digit sum fixes the chain steps at 240, whatever the leaf or TxID.
	RotatingWotscMaxOpcodeCost = 5881 + 41*240

	// RotatingWotscLeavesPerStage is the size of each stage's own tree.
	RotatingWotscLeavesPerStage = 64

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
	RotatingTripleWotscDisplayName = "Rotating triple WOTS+C (Falcon-1024 + WOTS+C + Ed25519)"
	RotatingTripleWotscDescription = "Fixed account address whose authorizing Falcon-1024, hash-based WOTS+C and Ed25519 stage program changes on every spend. Each stage has its own tree of 64 one-time keys. Not a standard construction. Signs only through rotating1."

	RotatingTripleXmssDisplayName = "Rotating triple XMSS (Falcon-1024 + XMSS + Ed25519)"
	RotatingTripleXmssDescription = "Fixed account address whose authorizing Falcon-1024, RFC 8391 XMSS and Ed25519 stage program changes on every spend. One XMSS tree serves 1,024 stages, each signing with its own 64 leaves. Signs only through the rotating1 flow."

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

	// StatelessHash reports a hash signature scheme that needs no one-time
	// leaf allocation or reuse history. Rotation/exposure monitoring still applies.
	StatelessHash bool

	// Preparation bounds local work, not signing authority or wire resources.
	// Zero limits preserve the caller's settings. These operational limits may
	// be tuned without changing stage addresses or the cryptographic contract.
	Preparation PreparationLimits

	// ReusedStageRestsOn names what a reused one-time stage still rests on,
	// for the reuse warning.
	ReusedStageRestsOn string

	// LeavesPerStage is how many one-time leaves a stage holds, 1 for a
	// family with one key per stage. StagesPerTree is how many consecutive
	// stages share one tree, 0 when every stage is its own tree. Together
	// they place a stage's leaf range: stage n's leaves are
	// (n mod StagesPerTree) * LeavesPerStage onward, or 0 onward when every
	// stage is its own tree.
	LeavesPerStage int
	StagesPerTree  int
}

// PreparationLimits prevents costly per-stage key generation from inheriting
// a shared-tree family's lookahead or request-time parallelism.
type PreparationLimits struct {
	MaxLookahead   uint64
	MaxDerivations int // per account per fill pass, or per request discovery
	MaxParallel    int
}

// LeafRange returns the leaf indices stage n may sign with, lo <= leaf < hi.
func (p Profile) LeafRange(stage uint64) (lo, hi uint64) {
	if p.LeavesPerStage <= 1 {
		return 0, 1
	}
	if p.StagesPerTree <= 0 {
		return 0, uint64(p.LeavesPerStage)
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
	RotatingTripleSlhdsaV1: {
		KeyType: RotatingTripleSlhdsaV1, Family: RotatingTripleSlhdsaFamily,
		DisplayName: RotatingTripleSlhdsaDisplayName, Description: RotatingTripleSlhdsaDescription,
		StagePublicKeySize: RotatingSlhdsaStagePublicKeySize,
		MaxProgramBytes:    RotatingSlhdsaMaxProgramBytes, MaxArgumentBytes: RotatingSlhdsaMaxArgumentBytes,
		MaxOpcodeCost: RotatingSlhdsaMaxOpcodeCost, StatelessHash: true,
		Preparation: PreparationLimits{MaxLookahead: 2, MaxDerivations: 4, MaxParallel: 1},
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
	RotatingTripleWotscV1: {
		KeyType:            RotatingTripleWotscV1,
		Family:             RotatingTripleWotscFamily,
		DisplayName:        RotatingTripleWotscDisplayName,
		Description:        RotatingTripleWotscDescription,
		StagePublicKeySize: RotatingWotscStagePublicKeySize,
		MaxProgramBytes:    RotatingWotscMaxProgramBytes,
		MaxArgumentBytes:   RotatingWotscMaxArgumentBytes,
		MaxOpcodeCost:      RotatingWotscMaxOpcodeCost,
		OneTimeStage:       true,
		ReusedStageRestsOn: "Falcon-1024 and Ed25519",
		LeavesPerStage:     RotatingWotscLeavesPerStage,
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
	return []string{RotatingTripleXmssV1, RotatingTripleSlhdsaV1, RotatingTripleWotscV1}
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
