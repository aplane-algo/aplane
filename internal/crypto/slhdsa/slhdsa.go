// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package slhdsa implements the SLH-DSA construction of FIPS 205 with
// SHA-256 throughout, n = 16, WOTS+ with w = 16 and FORS with k = 14 trees
// of height a = 12, for a choice of hypertree shape:
//
//   - SHA2128s is the standard SLH-DSA-SHA2-128s set, a hypertree of d = 7
//     layers of height h' = 9 (h = 63). Keys and signatures are
//     byte-compatible with FIPS 205; the NIST ACVP vectors in testdata are
//     pinned by the tests.
//   - Rescaled128 keeps every function of SHA2128s and shortens the
//     hypertree to d = 2 layers of height h' = 11 (h = 22). It is not a
//     FIPS 205 parameter set. It is sized for the rotating triple key type,
//     whose stage keys each sign a handful of messages, so that the
//     signature fits a smaller atomic group.
//
// The parameter set is a value of Params; the two sets share all code, so
// the ACVP vectors exercise the construction the rescaled set uses.
//
// It is written to be read next to its TEAL verifier: the verification
// path is deliberately plain, and VerifyStats reports the exact hash call
// profile a transcript of it would charge on the AVM.
//
// Only the pure (non-pre-hashed) external interface and the internal
// interface are provided.
package slhdsa

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/aplane-algo/aplane/internal/crypto"
)

const (
	// N is the security parameter and hash output size in bytes.
	N = 16
	// A is the height of one FORS tree and K the number of FORS trees.
	A = 12
	K = 14
	// LgW is log2 of the Winternitz parameter W; Len1 message digits, Len2
	// checksum digits, Len chains.
	LgW  = 4
	W    = 1 << LgW
	Len1 = N * 8 / LgW
	Len2 = 3
	Len  = Len1 + Len2
	// mdSize is the FORS part of the message digest, ceil(K*A/8).
	mdSize = (K*A + 7) / 8

	// PublicKeySize is seed || root; SigningKeySize is
	// SK.seed || SK.prf || PK.seed || PK.root.
	PublicKeySize  = 2 * N
	SigningKeySize = 4 * N

	// Signature layout: R || FORS signature || hypertree signature. The
	// hypertree part depends on the parameter set.
	ForsSignatureSize = K * (1 + A) * N
	WotsSignatureSize = Len * N

	// MaxContextSize bounds the context string of the external interface.
	MaxContextSize = 255

	// Address types, FIPS 205 section 4.2.
	addrWotsHash  = 0
	addrWotsPK    = 1
	addrTree      = 2
	addrForsTree  = 3
	addrForsRoots = 4
	addrWotsPRF   = 5
	addrForsPRF   = 6

	// adrsSize is the compressed SHA2 address: layer (1) || tree (8) ||
	// type (1) || three 4-byte words.
	adrsSize = 22
)

var (
	ErrSignatureSize = errors.New("slhdsa: wrong signature size")
	ErrVerify        = errors.New("slhdsa: signature does not verify")
	ErrContextSize   = errors.New("slhdsa: context longer than 255 bytes")
	ErrKeySize       = errors.New("slhdsa: wrong key size")
	ErrParams        = errors.New("slhdsa: invalid parameter set")
)

// Params is a hypertree shape for the construction: H is the hypertree
// height and D its number of layers. Everything else is fixed by the
// package constants. The derived fields are filled by NewParams.
type Params struct {
	Name string
	H, D uint32

	// HPrime is the height of one XMSS tree, H / D.
	HPrime uint32
	// idxTreeSize and idxLeafSize are the byte widths of the tree and leaf
	// indices in the message digest; M is the digest length.
	idxTreeSize, idxLeafSize int
	M                        int
	// XmssSignatureSize is one hypertree layer, HtSignatureSize all D
	// layers and SignatureSize the whole signature.
	XmssSignatureSize, HtSignatureSize, SignatureSize int
}

// NewParams derives a parameter set from a hypertree height and layer
// count. The height must split evenly into layers of at most 31 levels,
// the tree index must fit 63 bits and the digest must fit one MGF1 block.
func NewParams(name string, h, d uint32) (Params, error) {
	if d == 0 || h == 0 || h%d != 0 {
		return Params{}, fmt.Errorf("%w: height %d does not split into %d layers", ErrParams, h, d)
	}
	hPrime := h / d
	if hPrime > 31 || h-hPrime > 63 {
		return Params{}, fmt.Errorf("%w: height %d in %d layers is too tall", ErrParams, h, d)
	}
	p := Params{Name: name, H: h, D: d, HPrime: hPrime}
	p.idxTreeSize = int(h-hPrime+7) / 8
	p.idxLeafSize = int(hPrime+7) / 8
	p.M = mdSize + p.idxTreeSize + p.idxLeafSize
	if p.M > sha256.Size {
		return Params{}, fmt.Errorf("%w: digest of %d bytes needs more than one MGF1 block", ErrParams, p.M)
	}
	p.XmssSignatureSize = WotsSignatureSize + int(hPrime)*N
	p.HtSignatureSize = int(d) * p.XmssSignatureSize
	p.SignatureSize = N + ForsSignatureSize + p.HtSignatureSize
	return p, nil
}

func mustParams(name string, h, d uint32) Params {
	p, err := NewParams(name, h, d)
	if err != nil {
		panic(err)
	}
	return p
}

var (
	// SHA2128s is SLH-DSA-SHA2-128s of FIPS 205: h = 63 in seven layers.
	SHA2128s = mustParams("SLH-DSA-SHA2-128s", 63, 7)

	// Rescaled128 is the same construction with h = 22 in two layers of
	// height 11, a 4,400-byte signature. It is not a FIPS 205 parameter
	// set; its few-time security rests on a bound on signatures per key
	// that the rotating key type's design supplies.
	Rescaled128 = mustParams("SLH-DSA-SHA2-128 h=22 d=2", 22, 2)
)

// String reports the parameter set.
func (p *Params) String() string {
	return fmt.Sprintf("%s (n=%d h=%d d=%d a=%d k=%d w=%d, sig %d bytes)",
		p.Name, N, p.H, p.D, A, K, W, p.SignatureSize)
}

// PublicKey is PK.seed || PK.root.
type PublicKey struct {
	Seed [N]byte
	Root [N]byte
}

// Bytes returns the FIPS 205 encoding PK.seed || PK.root.
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

// SigningKey is the FIPS 205 private key SK.seed || SK.prf || PK.seed || PK.root.
type SigningKey struct {
	SKSeed [N]byte
	SKPrf  [N]byte
	Public PublicKey
}

// Zero erases the secret seeds.
func (sk *SigningKey) Zero() {
	crypto.ZeroBytes(sk.SKSeed[:])
	crypto.ZeroBytes(sk.SKPrf[:])
}

// Bytes returns the FIPS 205 encoding of the private key.
func (sk *SigningKey) Bytes() []byte {
	out := make([]byte, 0, SigningKeySize)
	out = append(out, sk.SKSeed[:]...)
	out = append(out, sk.SKPrf[:]...)
	out = append(out, sk.Public.Seed[:]...)
	return append(out, sk.Public.Root[:]...)
}

// ParseSigningKey parses the FIPS 205 private key encoding. The root is
// taken as stored, not recomputed.
func ParseSigningKey(b []byte) (*SigningKey, error) {
	if len(b) != SigningKeySize {
		return nil, ErrKeySize
	}
	sk := new(SigningKey)
	copy(sk.SKSeed[:], b[0:N])
	copy(sk.SKPrf[:], b[N:2*N])
	copy(sk.Public.Seed[:], b[2*N:3*N])
	copy(sk.Public.Root[:], b[3*N:])
	return sk, nil
}

// address is the compressed 22-byte SHA2 ADRS.
type address [adrsSize]byte

func (a *address) setLayer(l uint32)      { a[0] = byte(l) }
func (a *address) setTree(t uint64)       { binary.BigEndian.PutUint64(a[1:9], t) }
func (a *address) setType(t byte)         { a[9] = t; clear(a[10:]) }
func (a *address) setKeyPair(i uint32)    { binary.BigEndian.PutUint32(a[10:14], i) }
func (a *address) keyPair() uint32        { return binary.BigEndian.Uint32(a[10:14]) }
func (a *address) setChain(i uint32)      { binary.BigEndian.PutUint32(a[14:18], i) }
func (a *address) setTreeHeight(i uint32) { binary.BigEndian.PutUint32(a[14:18], i) }
func (a *address) setHash(i uint32)       { binary.BigEndian.PutUint32(a[18:22], i) }
func (a *address) setTreeIndex(i uint32)  { binary.BigEndian.PutUint32(a[18:22], i) }

// Stats counts the hash calls of one operation, by FIPS 205 function.
// Chain is the number of WOTS+ chain steps (each one F call) and is
// included in F. Every entry is one SHA-256 compression-function-bearing
// call as the AVM would charge it, except that TLen inputs are long.
type Stats struct {
	F, H, PRF, TLen, HMsg int
	Chain                 int
}

// Hashes returns the total SHA-256 invocations.
func (s Stats) Hashes() int { return s.F + s.H + s.PRF + s.TLen + s.HMsg }

// hasher carries a key's SHA-256 midstate over PK.seed || toByte(0, 48),
// the one-block prefix shared by F, H, T_l and PRF for n = 16, and the
// parameter set of the key. A value is not safe for concurrent use.
type hasher struct {
	p     *Params
	state []byte
	h     hash.Hash
	in    [adrsSize + Len*N]byte
	out   [sha256.Size]byte
	stats *Stats
}

// freshState is the serialized state of an empty SHA-256.
var freshState = func() []byte {
	state, err := sha256.New().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return state
}()

func newHasher(p *Params, pkSeed *[N]byte, stats *Stats) *hasher {
	var block [sha256.BlockSize]byte
	copy(block[:], pkSeed[:])
	h := sha256.New()
	h.Write(block[:])
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return &hasher{p: p, state: state, h: h, stats: stats}
}

func (hs *hasher) zero() {
	crypto.ZeroBytes(hs.state)
	crypto.ZeroBytes(hs.in[:])
	crypto.ZeroBytes(hs.out[:])
	if err := hs.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(freshState); err != nil {
		panic(err)
	}
}

// sum returns Trunc_n(SHA-256(PK.seed || 0^48 || adrs || parts...)).
func (hs *hasher) sum(adrs *address, parts ...[]byte) (out [N]byte) {
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

func (hs *hasher) f(adrs *address, m *[N]byte) [N]byte {
	if hs.stats != nil {
		hs.stats.F++
	}
	return hs.sum(adrs, m[:])
}

func (hs *hasher) h2(adrs *address, l, r *[N]byte) [N]byte {
	if hs.stats != nil {
		hs.stats.H++
	}
	return hs.sum(adrs, l[:], r[:])
}

func (hs *hasher) tl(adrs *address, m []byte) [N]byte {
	if hs.stats != nil {
		hs.stats.TLen++
	}
	return hs.sum(adrs, m)
}

func (hs *hasher) prf(adrs *address, skSeed *[N]byte) [N]byte {
	if hs.stats != nil {
		hs.stats.PRF++
	}
	return hs.sum(adrs, skSeed[:])
}

// prfMsg is PRF_msg(SK.prf, opt_rand, M) = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M)).
func prfMsg(skPrf, optRand *[N]byte, msg []byte) (out [N]byte) {
	mac := hmac.New(sha256.New, skPrf[:])
	mac.Write(optRand[:])
	mac.Write(msg)
	var full [sha256.Size]byte
	mac.Sum(full[:0])
	copy(out[:], full[:N])
	crypto.ZeroBytes(full[:])
	return out
}

// hashMsg is H_msg(R, PK.seed, PK.root, M) =
// MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m).
// NewParams requires m <= 32, so one MGF1 block suffices; the counter is 0.
func hashMsg(p *Params, r *[N]byte, pk *PublicKey, msg []byte, stats *Stats) []byte {
	inner := sha256.New()
	inner.Write(r[:])
	inner.Write(pk.Seed[:])
	inner.Write(pk.Root[:])
	inner.Write(msg)
	var seed [2*N + sha256.Size + 4]byte
	copy(seed[:N], r[:])
	copy(seed[N:2*N], pk.Seed[:])
	inner.Sum(seed[2*N : 2*N])
	// seed[2N+32:] is the big-endian MGF1 counter, 0.
	out := sha256.Sum256(seed[:])
	if stats != nil {
		stats.HMsg += 2
	}
	return out[:p.M]
}

// base2b splits in into outLen base-2^b digits, FIPS 205 algorithm 4.
func base2b(in []byte, b uint, outLen int) []uint32 {
	out := make([]uint32, outLen)
	var (
		idx  int
		bits uint
		acc  uint64
	)
	for i := range out {
		for bits < b {
			acc = acc<<8 | uint64(in[idx])
			idx++
			bits += 8
		}
		bits -= b
		out[i] = uint32(acc>>bits) & (1<<b - 1)
	}
	return out
}

// wotsDigits returns the Len base-w digits of msg with its checksum,
// FIPS 205 algorithms 7 and 8.
func wotsDigits(msg *[N]byte) [Len]uint32 {
	var digits [Len]uint32
	copy(digits[:Len1], base2b(msg[:], LgW, Len1))
	csum := uint32(0)
	for _, d := range digits[:Len1] {
		csum += W - 1 - d
	}
	csum <<= (8 - (Len2*LgW)%8) % 8
	var cb [(Len2*LgW + 7) / 8]byte
	binary.BigEndian.PutUint16(cb[:], uint16(csum))
	copy(digits[Len1:], base2b(cb[:], LgW, Len2))
	return digits
}

// chain applies F steps times starting at index start, FIPS 205 algorithm 5.
func (hs *hasher) chain(adrs *address, x [N]byte, start, steps uint32) [N]byte {
	for j := start; j < start+steps; j++ {
		adrs.setHash(j)
		x = hs.f(adrs, &x)
		if hs.stats != nil {
			hs.stats.Chain++
		}
	}
	return x
}

// wotsPKGen returns the WOTS+ public key of the key pair adrs addresses,
// FIPS 205 algorithm 6.
func (hs *hasher) wotsPKGen(skSeed *[N]byte, adrs *address) [N]byte {
	skAdrs := *adrs
	skAdrs.setType(addrWotsPRF)
	skAdrs.setKeyPair(adrs.keyPair())
	var tmp [Len * N]byte
	for i := uint32(0); i < Len; i++ {
		skAdrs.setChain(i)
		sk := hs.prf(&skAdrs, skSeed)
		adrs.setChain(i)
		pk := hs.chain(adrs, sk, 0, W-1)
		copy(tmp[i*N:], pk[:])
		crypto.ZeroBytes(sk[:])
	}
	pkAdrs := *adrs
	pkAdrs.setType(addrWotsPK)
	pkAdrs.setKeyPair(adrs.keyPair())
	return hs.tl(&pkAdrs, tmp[:])
}

// wotsSign writes the WOTS+ signature of msg into sig, FIPS 205 algorithm 7.
func (hs *hasher) wotsSign(sig []byte, msg *[N]byte, skSeed *[N]byte, adrs *address) {
	digits := wotsDigits(msg)
	skAdrs := *adrs
	skAdrs.setType(addrWotsPRF)
	skAdrs.setKeyPair(adrs.keyPair())
	for i := uint32(0); i < Len; i++ {
		skAdrs.setChain(i)
		sk := hs.prf(&skAdrs, skSeed)
		adrs.setChain(i)
		s := hs.chain(adrs, sk, 0, digits[i])
		copy(sig[i*N:], s[:])
		crypto.ZeroBytes(sk[:])
	}
}

// wotsPKFromSig recovers the WOTS+ public key from a signature, FIPS 205
// algorithm 8.
func (hs *hasher) wotsPKFromSig(sig []byte, msg *[N]byte, adrs *address) [N]byte {
	digits := wotsDigits(msg)
	var tmp [Len * N]byte
	for i := uint32(0); i < Len; i++ {
		adrs.setChain(i)
		var s [N]byte
		copy(s[:], sig[i*N:(i+1)*N])
		pk := hs.chain(adrs, s, digits[i], W-1-digits[i])
		copy(tmp[i*N:], pk[:])
	}
	pkAdrs := *adrs
	pkAdrs.setType(addrWotsPK)
	pkAdrs.setKeyPair(adrs.keyPair())
	return hs.tl(&pkAdrs, tmp[:])
}

// xmssNode computes node i at height z of the XMSS tree adrs addresses,
// FIPS 205 algorithm 9.
func (hs *hasher) xmssNode(skSeed *[N]byte, i, z uint32, adrs *address) [N]byte {
	if z == 0 {
		adrs.setType(addrWotsHash)
		adrs.setKeyPair(i)
		return hs.wotsPKGen(skSeed, adrs)
	}
	l := hs.xmssNode(skSeed, 2*i, z-1, adrs)
	r := hs.xmssNode(skSeed, 2*i+1, z-1, adrs)
	adrs.setType(addrTree)
	adrs.setTreeHeight(z)
	adrs.setTreeIndex(i)
	return hs.h2(adrs, &l, &r)
}

// xmssSign writes the XMSS signature of msg under leaf idx, FIPS 205
// algorithm 10.
func (hs *hasher) xmssSign(sig []byte, msg *[N]byte, skSeed *[N]byte, idx uint32, adrs *address) {
	auth := sig[WotsSignatureSize:]
	for j := uint32(0); j < hs.p.HPrime; j++ {
		k := (idx >> j) ^ 1
		node := hs.xmssNode(skSeed, k, j, adrs)
		copy(auth[j*N:], node[:])
	}
	adrs.setType(addrWotsHash)
	adrs.setKeyPair(idx)
	hs.wotsSign(sig[:WotsSignatureSize], msg, skSeed, adrs)
}

// xmssPKFromSig recovers the XMSS root from a signature, FIPS 205
// algorithm 11.
func (hs *hasher) xmssPKFromSig(idx uint32, sig []byte, msg *[N]byte, adrs *address) [N]byte {
	adrs.setType(addrWotsHash)
	adrs.setKeyPair(idx)
	node := hs.wotsPKFromSig(sig[:WotsSignatureSize], msg, adrs)
	auth := sig[WotsSignatureSize:]
	adrs.setType(addrTree)
	adrs.setTreeIndex(idx)
	treeIndex := idx
	for k := uint32(0); k < hs.p.HPrime; k++ {
		adrs.setTreeHeight(k + 1)
		var sib [N]byte
		copy(sib[:], auth[k*N:(k+1)*N])
		if (idx>>k)&1 == 0 {
			treeIndex /= 2
			adrs.setTreeIndex(treeIndex)
			node = hs.h2(adrs, &node, &sib)
		} else {
			treeIndex = (treeIndex - 1) / 2
			adrs.setTreeIndex(treeIndex)
			node = hs.h2(adrs, &sib, &node)
		}
	}
	return node
}

// htSign writes the hypertree signature of msg, FIPS 205 algorithm 12.
func (hs *hasher) htSign(sig []byte, msg *[N]byte, skSeed *[N]byte, idxTree uint64, idxLeaf uint32) {
	p := hs.p
	layerSize := p.XmssSignatureSize
	var adrs address
	adrs.setLayer(0)
	adrs.setTree(idxTree)
	hs.xmssSign(sig[:layerSize], msg, skSeed, idxLeaf, &adrs)
	root := hs.xmssPKFromSig(idxLeaf, sig[:layerSize], msg, &adrs)
	for j := uint32(1); j < p.D; j++ {
		idxLeaf = uint32(idxTree & (1<<p.HPrime - 1))
		idxTree >>= p.HPrime
		adrs.setLayer(j)
		adrs.setTree(idxTree)
		layer := sig[int(j)*layerSize : int(j+1)*layerSize]
		hs.xmssSign(layer, &root, skSeed, idxLeaf, &adrs)
		if j < p.D-1 {
			root = hs.xmssPKFromSig(idxLeaf, layer, &root, &adrs)
		}
	}
}

// htVerify checks a hypertree signature against root, FIPS 205 algorithm 13.
func (hs *hasher) htVerify(msg *[N]byte, sig []byte, pkRoot *[N]byte, idxTree uint64, idxLeaf uint32) bool {
	p := hs.p
	layerSize := p.XmssSignatureSize
	var adrs address
	adrs.setLayer(0)
	adrs.setTree(idxTree)
	node := hs.xmssPKFromSig(idxLeaf, sig[:layerSize], msg, &adrs)
	for j := uint32(1); j < p.D; j++ {
		idxLeaf = uint32(idxTree & (1<<p.HPrime - 1))
		idxTree >>= p.HPrime
		adrs.setLayer(j)
		adrs.setTree(idxTree)
		layer := sig[int(j)*layerSize : int(j+1)*layerSize]
		node = hs.xmssPKFromSig(idxLeaf, layer, &node, &adrs)
	}
	return subtle.ConstantTimeCompare(node[:], pkRoot[:]) == 1
}

// forsSKGen returns FORS secret value idx, FIPS 205 algorithm 14.
func (hs *hasher) forsSKGen(skSeed *[N]byte, adrs *address, idx uint32) [N]byte {
	skAdrs := *adrs
	skAdrs.setType(addrForsPRF)
	skAdrs.setKeyPair(adrs.keyPair())
	skAdrs.setTreeHeight(0)
	skAdrs.setTreeIndex(idx)
	return hs.prf(&skAdrs, skSeed)
}

// forsNode computes node i at height z of the FORS forest, FIPS 205
// algorithm 15.
func (hs *hasher) forsNode(skSeed *[N]byte, i, z uint32, adrs *address) [N]byte {
	if z == 0 {
		sk := hs.forsSKGen(skSeed, adrs, i)
		adrs.setTreeHeight(0)
		adrs.setTreeIndex(i)
		node := hs.f(adrs, &sk)
		crypto.ZeroBytes(sk[:])
		return node
	}
	l := hs.forsNode(skSeed, 2*i, z-1, adrs)
	r := hs.forsNode(skSeed, 2*i+1, z-1, adrs)
	adrs.setTreeHeight(z)
	adrs.setTreeIndex(i)
	return hs.h2(adrs, &l, &r)
}

// forsSign writes the FORS signature of md, FIPS 205 algorithm 16.
func (hs *hasher) forsSign(sig []byte, md []byte, skSeed *[N]byte, adrs *address) {
	indices := base2b(md, A, K)
	for i := uint32(0); i < K; i++ {
		entry := sig[i*(1+A)*N:]
		sk := hs.forsSKGen(skSeed, adrs, i<<A+indices[i])
		copy(entry[:N], sk[:])
		crypto.ZeroBytes(sk[:])
		for j := uint32(0); j < A; j++ {
			s := (indices[i] >> j) ^ 1
			node := hs.forsNode(skSeed, i<<(A-j)+s, j, adrs)
			copy(entry[(1+j)*N:], node[:])
		}
	}
}

// forsPKFromSig recovers the FORS public key from a signature, FIPS 205
// algorithm 17.
func (hs *hasher) forsPKFromSig(sig []byte, md []byte, adrs *address) [N]byte {
	indices := base2b(md, A, K)
	var roots [K * N]byte
	for i := uint32(0); i < K; i++ {
		entry := sig[i*(1+A)*N:]
		var sk [N]byte
		copy(sk[:], entry[:N])
		adrs.setTreeHeight(0)
		treeIndex := i<<A + indices[i]
		adrs.setTreeIndex(treeIndex)
		node := hs.f(adrs, &sk)
		auth := entry[N:]
		for j := uint32(0); j < A; j++ {
			adrs.setTreeHeight(j + 1)
			var sib [N]byte
			copy(sib[:], auth[j*N:(j+1)*N])
			if (indices[i]>>j)&1 == 0 {
				treeIndex /= 2
				adrs.setTreeIndex(treeIndex)
				node = hs.h2(adrs, &node, &sib)
			} else {
				treeIndex = (treeIndex - 1) / 2
				adrs.setTreeIndex(treeIndex)
				node = hs.h2(adrs, &sib, &node)
			}
		}
		copy(roots[i*N:], node[:])
	}
	pkAdrs := *adrs
	pkAdrs.setType(addrForsRoots)
	pkAdrs.setKeyPair(adrs.keyPair())
	return hs.tl(&pkAdrs, roots[:])
}

// splitDigest parses H_msg output into md, idx_tree and idx_leaf, FIPS 205
// algorithm 19 steps 7 to 12.
func (p *Params) splitDigest(digest []byte) (md []byte, idxTree uint64, idxLeaf uint32) {
	md = digest[:mdSize]
	var tb [8]byte
	copy(tb[8-p.idxTreeSize:], digest[mdSize:mdSize+p.idxTreeSize])
	idxTree = binary.BigEndian.Uint64(tb[:]) & (1<<(p.H-p.HPrime) - 1)
	var lb [4]byte
	copy(lb[4-p.idxLeafSize:], digest[mdSize+p.idxTreeSize:])
	idxLeaf = binary.BigEndian.Uint32(lb[:]) & (1<<p.HPrime - 1)
	return md, idxTree, idxLeaf
}

// KeyGenFromSeeds derives a key pair from the three seeds, FIPS 205
// algorithm 18.
func (p *Params) KeyGenFromSeeds(skSeed, skPrf, pkSeed *[N]byte) *SigningKey {
	sk := &SigningKey{SKSeed: *skSeed, SKPrf: *skPrf}
	sk.Public.Seed = *pkSeed
	hs := newHasher(p, pkSeed, nil)
	defer hs.zero()
	var adrs address
	adrs.setLayer(p.D - 1)
	sk.Public.Root = hs.xmssNode(&sk.SKSeed, 0, p.HPrime, &adrs)
	return sk
}

// SignInternal is slh_sign_internal, FIPS 205 algorithm 19. optRand is the
// additional randomness; the deterministic variant passes PK.seed.
func (p *Params) SignInternal(sk *SigningKey, msg []byte, optRand *[N]byte) []byte {
	sig := make([]byte, p.SignatureSize)
	r := prfMsg(&sk.SKPrf, optRand, msg)
	copy(sig[:N], r[:])
	digest := hashMsg(p, &r, &sk.Public, msg, nil)
	md, idxTree, idxLeaf := p.splitDigest(digest)

	hs := newHasher(p, &sk.Public.Seed, nil)
	defer hs.zero()
	var adrs address
	adrs.setTree(idxTree)
	adrs.setType(addrForsTree)
	adrs.setKeyPair(idxLeaf)
	forsSig := sig[N : N+ForsSignatureSize]
	hs.forsSign(forsSig, md, &sk.SKSeed, &adrs)
	pkFors := hs.forsPKFromSig(forsSig, md, &adrs)
	hs.htSign(sig[N+ForsSignatureSize:], &pkFors, &sk.SKSeed, idxTree, idxLeaf)
	return sig
}

// VerifyInternal is slh_verify_internal, FIPS 205 algorithm 20.
func (p *Params) VerifyInternal(pk *PublicKey, msg, sig []byte) error {
	_, err := p.verifyInternal(pk, msg, sig, false)
	return err
}

// VerifyStats verifies like VerifyInternal and also reports the hash call
// profile of the run. On a failing signature the stats cover the work done
// before the mismatch was found.
func (p *Params) VerifyStats(pk *PublicKey, msg, sig []byte) (Stats, error) {
	return p.verifyInternal(pk, msg, sig, true)
}

func (p *Params) verifyInternal(pk *PublicKey, msg, sig []byte, count bool) (Stats, error) {
	var stats Stats
	var sp *Stats
	if count {
		sp = &stats
	}
	if len(sig) != p.SignatureSize {
		return stats, ErrSignatureSize
	}
	var r [N]byte
	copy(r[:], sig[:N])
	digest := hashMsg(p, &r, pk, msg, sp)
	md, idxTree, idxLeaf := p.splitDigest(digest)

	hs := newHasher(p, &pk.Seed, sp)
	var adrs address
	adrs.setTree(idxTree)
	adrs.setType(addrForsTree)
	adrs.setKeyPair(idxLeaf)
	pkFors := hs.forsPKFromSig(sig[N:N+ForsSignatureSize], md, &adrs)
	if !hs.htVerify(&pkFors, sig[N+ForsSignatureSize:], &pk.Root, idxTree, idxLeaf) {
		return stats, ErrVerify
	}
	return stats, nil
}

// messagePrime builds M' = 0x00 || len(ctx) || ctx || M for the pure
// external interface, FIPS 205 algorithms 22 and 24.
func messagePrime(ctx, msg []byte) ([]byte, error) {
	if len(ctx) > MaxContextSize {
		return nil, ErrContextSize
	}
	out := make([]byte, 0, 2+len(ctx)+len(msg))
	out = append(out, 0, byte(len(ctx)))
	out = append(out, ctx...)
	return append(out, msg...), nil
}

// Sign is the pure external interface slh_sign, FIPS 205 algorithm 22,
// with optRand as the additional randomness (nil selects the deterministic
// variant, which uses PK.seed).
func (p *Params) Sign(sk *SigningKey, msg, ctx []byte, optRand *[N]byte) ([]byte, error) {
	mp, err := messagePrime(ctx, msg)
	if err != nil {
		return nil, err
	}
	if optRand == nil {
		optRand = &sk.Public.Seed
	}
	return p.SignInternal(sk, mp, optRand), nil
}

// Verify is the pure external interface slh_verify, FIPS 205 algorithm 24.
func (p *Params) Verify(pk *PublicKey, msg, sig, ctx []byte) error {
	mp, err := messagePrime(ctx, msg)
	if err != nil {
		return err
	}
	return p.VerifyInternal(pk, mp, sig)
}
