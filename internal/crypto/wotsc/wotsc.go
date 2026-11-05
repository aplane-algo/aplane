// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package wotsc implements a Merkle tree of 64 WOTS+C one-time keys over
// SHA-256, n = 16, w = 16, with the FIPS 205 SHA2 tweakable hash and address
// layout. WOTS+C replaces the WOTS+ checksum with a fixed digit sum: the
// signer searches randomizers until the message digest's 32 digits sum to
// exactly TargetSum, and the verifier requires that sum.
//
// This is not a standard. It is the hash-based leg of the rotating WOTS+C
// triple key type, whose every stage also requires Falcon-1024 and Ed25519,
// and it signs only 32-byte messages (a TxID). Signing a second message on a
// leaf that has already signed one breaks that leaf's one-time claim; this
// package does not track leaves, so the caller chooses them.
//
// It is written to be read next to its TEAL verifier. Verification is
// deliberately plain and performs a fixed number of hash calls:
// VerifyHashCalls.
package wotsc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/aplane-algo/aplane/internal/crypto"
)

const (
	// N is the hash output and seed size in bytes.
	N = 16
	// W is the Winternitz parameter and Len the number of chains. A digit is
	// one nibble, so a digest of N bytes gives exactly Len digits.
	W   = 16
	Len = 2 * N
	// TargetSum is the digit sum of every accepted digest. It is the most
	// likely sum, Len * (W-1) / 2, so the search is as short as it can be.
	TargetSum = 240
	// Height is the tree height and Leaves the number of one-time keys.
	Height = 6
	Leaves = 1 << Height
	// GrindLimit bounds the randomizer search. One candidate qualifies with
	// probability about 1/66, so reaching the limit has probability about
	// 2^-181.
	GrindLimit = 8192
	// MessageSize is the only message length: a TxID.
	MessageSize = 32

	// PublicKeySize is PK.seed || PK.root.
	PublicKeySize = 2 * N
	// SignatureSize is leaf (4) || R || chain values || authentication path.
	SignatureSize = 4 + N + Len*N + Height*N

	// VerifyHashCalls is the number of SHA-256 calls in an accepted
	// verification: the digest, the chain steps, the leaf compression and the
	// tree nodes. It is constant: each chain runs W-1-digit steps, so the 32
	// chains always run Len*(W-1) - TargetSum = 240 in total.
	VerifyHashCalls = 1 + Len*(W-1) - TargetSum + 1 + Height

	// Offsets into a signature.
	offsetR      = 4
	offsetChains = offsetR + N
	offsetAuth   = offsetChains + Len*N

	// Address types, FIPS 205 section 4.2.
	addrWotsHash = 0
	addrWotsPK   = 1
	addrTree     = 2
	addrWotsPRF  = 5

	// adrsSize is the compressed SHA2 address: layer (1) || tree (8) ||
	// type (1) || three 4-byte words.
	adrsSize = 22

	// nodeCount sizes the tree in heap order: the root is node 1 and leaf i
	// is node Leaves+i.
	nodeCount = 2 * Leaves
)

var (
	ErrSignatureSize = errors.New("wotsc: wrong signature size")
	ErrMessageSize   = errors.New("wotsc: wrong message size")
	ErrLeafIndex     = errors.New("wotsc: leaf index out of range")
	ErrVerify        = errors.New("wotsc: signature does not verify")
	ErrGrindLimit    = errors.New("wotsc: no randomizer reached the digit sum")
	ErrKeySize       = errors.New("wotsc: wrong key size")
)

// PublicKey is PK.seed || PK.root.
type PublicKey struct {
	Seed [N]byte
	Root [N]byte
}

// Bytes returns PK.seed || PK.root.
func (pk *PublicKey) Bytes() []byte {
	out := make([]byte, 0, PublicKeySize)
	out = append(out, pk.Seed[:]...)
	return append(out, pk.Root[:]...)
}

// ParsePublicKey parses PK.seed || PK.root.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrKeySize
	}
	pk := new(PublicKey)
	copy(pk.Seed[:], b[:N])
	copy(pk.Root[:], b[N:])
	return pk, nil
}

// SigningKey is one tree. The tree nodes are public; the seeds are not.
type SigningKey struct {
	SKSeed [N]byte
	SKPrf  [N]byte
	Public PublicKey
	nodes  [nodeCount][N]byte
}

// Zero erases the secret seeds.
func (sk *SigningKey) Zero() {
	crypto.ZeroBytes(sk.SKSeed[:])
	crypto.ZeroBytes(sk.SKPrf[:])
}

// address is the compressed 22-byte SHA2 ADRS. Layer and tree stay zero.
type address [adrsSize]byte

func (a *address) setType(t byte)      { a[9] = t; clear(a[10:]) }
func (a *address) setKeyPair(i uint32) { binary.BigEndian.PutUint32(a[10:14], i) }
func (a *address) setChain(i uint32)   { binary.BigEndian.PutUint32(a[14:18], i) }
func (a *address) setHash(i uint32)    { binary.BigEndian.PutUint32(a[18:22], i) }

// hasher carries a key's SHA-256 midstate over PK.seed || toByte(0, 48), the
// one-block prefix of every tweakable hash. A value is not safe for
// concurrent use.
type hasher struct {
	state []byte
	h     hash.Hash
	in    [adrsSize + Len*N]byte
	out   [sha256.Size]byte
}

// freshState is the serialized state of an empty SHA-256.
var freshState = func() []byte {
	state, err := sha256.New().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return state
}()

func newHasher(pkSeed *[N]byte) *hasher {
	var block [sha256.BlockSize]byte
	copy(block[:], pkSeed[:])
	h := sha256.New()
	h.Write(block[:])
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return &hasher{state: state, h: h}
}

func (hs *hasher) zero() {
	crypto.ZeroBytes(hs.state)
	crypto.ZeroBytes(hs.in[:])
	crypto.ZeroBytes(hs.out[:])
	if err := hs.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(freshState); err != nil {
		panic(err)
	}
}

// th returns Trunc_n(SHA-256(PK.seed || 0^48 || adrs || parts...)).
func (hs *hasher) th(adrs *address, parts ...[]byte) (out [N]byte) {
	if err := hs.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(hs.state); err != nil {
		panic(err)
	}
	n := copy(hs.in[:], adrs[:])
	for _, p := range parts {
		n += copy(hs.in[n:], p)
	}
	hs.h.Write(hs.in[:n])
	hs.h.Sum(hs.out[:0])
	copy(out[:], hs.out[:N])
	return out
}

// chain applies steps hash steps from position start of chain j of leaf i.
func (hs *hasher) chain(x [N]byte, start, steps, i, j uint32) [N]byte {
	var adrs address
	adrs.setType(addrWotsHash)
	adrs.setKeyPair(i)
	adrs.setChain(j)
	for k := start; k < start+steps; k++ {
		adrs.setHash(k)
		x = hs.th(&adrs, x[:])
	}
	return x
}

// chainSecret is the secret start of chain j of leaf i.
func (hs *hasher) chainSecret(skSeed *[N]byte, i, j uint32) [N]byte {
	var adrs address
	adrs.setType(addrWotsPRF)
	adrs.setKeyPair(i)
	adrs.setChain(j)
	return hs.th(&adrs, skSeed[:])
}

// compress hashes the chain ends of leaf i into its tree leaf.
func (hs *hasher) compress(ends []byte, i uint32) [N]byte {
	var adrs address
	adrs.setType(addrWotsPK)
	adrs.setKeyPair(i)
	return hs.th(&adrs, ends)
}

// parent hashes two children into the node at height, index.
func (hs *hasher) parent(left, right *[N]byte, height, index uint32) [N]byte {
	var adrs address
	adrs.setType(addrTree)
	adrs.setChain(height)
	adrs.setHash(index)
	return hs.th(&adrs, left[:], right[:])
}

// NewSigningKey builds the tree of the given seeds.
func NewSigningKey(skSeed, skPrf, pkSeed *[N]byte) *SigningKey {
	sk := &SigningKey{SKSeed: *skSeed, SKPrf: *skPrf}
	sk.Public.Seed = *pkSeed
	hs := newHasher(pkSeed)
	defer hs.zero()

	var ends [Len * N]byte
	for i := uint32(0); i < Leaves; i++ {
		for j := uint32(0); j < Len; j++ {
			x := hs.chainSecret(skSeed, i, j)
			end := hs.chain(x, 0, W-1, i, j)
			crypto.ZeroBytes(x[:])
			copy(ends[j*N:], end[:])
		}
		sk.nodes[Leaves+i] = hs.compress(ends[:], i)
	}
	for height, first := uint32(1), uint32(Leaves/2); first >= 1; height, first = height+1, first/2 {
		for index := uint32(0); index < first; index++ {
			node := first + index
			sk.nodes[node] = hs.parent(&sk.nodes[2*node], &sk.nodes[2*node+1], height, index)
		}
	}
	sk.Public.Root = sk.nodes[1]
	return sk
}

// Digits returns the digits the verifier reads for randomizer r on a leaf,
// high nibble first, and their sum.
func Digits(pk *PublicKey, r *[N]byte, leaf uint32, msg []byte) ([Len]byte, int) {
	h := sha256.New()
	h.Write(pk.Seed[:])
	h.Write(pk.Root[:])
	h.Write(r[:])
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], leaf)
	h.Write(index[:])
	h.Write(msg)
	var full [sha256.Size]byte
	h.Sum(full[:0])

	var digits [Len]byte
	sum := 0
	for i := range N {
		digits[2*i], digits[2*i+1] = full[i]>>4, full[i]&0x0f
		sum += int(digits[2*i]) + int(digits[2*i+1])
	}
	return digits, sum
}

// randomizer is candidate ctr of the search for a leaf and message.
func randomizer(skPrf *[N]byte, leaf uint32, msg []byte, ctr uint32) [N]byte {
	var in [N + 4 + MessageSize + 4]byte
	copy(in[:], skPrf[:])
	binary.BigEndian.PutUint32(in[N:], leaf)
	copy(in[N+4:], msg)
	binary.BigEndian.PutUint32(in[N+4+MessageSize:], ctr)
	full := sha256.Sum256(in[:])
	var r [N]byte
	copy(r[:], full[:N])
	crypto.ZeroBytes(in[:])
	crypto.ZeroBytes(full[:])
	return r
}

// grind searches counters below limit in order and returns the first
// randomizer whose digits reach TargetSum. The search is deterministic, so a
// retry of the same leaf and message reproduces the same signature.
func (sk *SigningKey) grind(leaf uint32, msg []byte, limit uint32) (r [N]byte, digits [Len]byte, ctr uint32, err error) {
	for ctr = range limit {
		r = randomizer(&sk.SKPrf, leaf, msg, ctr)
		var sum int
		digits, sum = Digits(&sk.Public, &r, leaf, msg)
		if sum == TargetSum {
			return r, digits, ctr, nil
		}
	}
	return [N]byte{}, [Len]byte{}, 0, ErrGrindLimit
}

// Sign signs a 32-byte message with the given leaf. The caller owns the
// one-time rule. If the search finds no randomizer, no signature is made.
func (sk *SigningKey) Sign(leaf uint32, msg []byte) ([]byte, error) {
	if leaf >= Leaves {
		return nil, ErrLeafIndex
	}
	if len(msg) != MessageSize {
		return nil, ErrMessageSize
	}
	r, digits, _, err := sk.grind(leaf, msg, GrindLimit)
	if err != nil {
		return nil, err
	}
	hs := newHasher(&sk.Public.Seed)
	defer hs.zero()

	sig := make([]byte, 0, SignatureSize)
	sig = binary.BigEndian.AppendUint32(sig, leaf)
	sig = append(sig, r[:]...)
	for j := uint32(0); j < Len; j++ {
		x := hs.chainSecret(&sk.SKSeed, leaf, j)
		value := hs.chain(x, 0, uint32(digits[j]), leaf, j)
		crypto.ZeroBytes(x[:])
		sig = append(sig, value[:]...)
	}
	for node := Leaves + leaf; node > 1; node /= 2 {
		sig = append(sig, sk.nodes[node^1][:]...)
	}
	return sig, nil
}

// Verify checks a signature against a public key. It rejects a wrong size, a
// leaf outside the tree and any digest whose digits don't sum to TargetSum.
func Verify(pk *PublicKey, msg, sig []byte) error {
	if len(msg) != MessageSize {
		return ErrMessageSize
	}
	if len(sig) != SignatureSize {
		return ErrSignatureSize
	}
	leaf := binary.BigEndian.Uint32(sig)
	if leaf >= Leaves {
		return ErrVerify
	}
	var r [N]byte
	copy(r[:], sig[offsetR:])
	digits, sum := Digits(pk, &r, leaf, msg)
	// Without this check a digest of high digits forges from any signature,
	// because anyone can hash a revealed value further along its chain.
	if sum != TargetSum {
		return ErrVerify
	}

	hs := newHasher(&pk.Seed)
	defer hs.zero()
	var ends [Len * N]byte
	for j := uint32(0); j < Len; j++ {
		var x [N]byte
		copy(x[:], sig[offsetChains+j*N:])
		d := uint32(digits[j])
		end := hs.chain(x, d, W-1-d, leaf, j)
		copy(ends[j*N:], end[:])
	}
	node := hs.compress(ends[:], leaf)
	index := leaf
	for z := uint32(0); z < Height; z++ {
		var sibling [N]byte
		copy(sibling[:], sig[offsetAuth+z*N:])
		bit := index & 1
		index >>= 1
		if bit == 1 {
			node = hs.parent(&sibling, &node, z+1, index)
		} else {
			node = hs.parent(&node, &sibling, z+1, index)
		}
	}
	if subtle.ConstantTimeCompare(node[:], pk.Root[:]) != 1 {
		return ErrVerify
	}
	return nil
}
