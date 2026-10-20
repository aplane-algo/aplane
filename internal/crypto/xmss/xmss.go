// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package xmss implements the XMSS-SHA2_16_256 parameter set of RFC 8391:
// SHA-256, n = 32, w = 16, h = 16, WOTS+ with bitmasks, L-trees and a
// single hash tree. Public keys and signatures are byte-compatible with the
// XMSS reference implementation (testdata/vectors.json is generated from an
// independent implementation checked against it, and the reference's own
// test vector is pinned in the tests).
//
// The package is stateless: Sign takes the index it is told to use. Index
// management is the caller's responsibility; see lsig/rotatingxmsstriple.
package xmss

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"fmt"
	"hash"
	"runtime"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
)

const (
	// N is the security parameter and hash output size in bytes.
	N = 32
	// W is the Winternitz parameter; Steps is the chain length W-1.
	W     = 16
	Steps = W - 1
	// Len1 message digits, Len2 checksum digits, Len chains.
	Len1 = 64
	Len2 = 3
	Len  = Len1 + Len2
	// Height is the tree height; Leaves the number of one-time keys.
	Height = 16
	Leaves = 1 << Height

	// OID is the RFC 8391 identifier of XMSS-SHA2_16_256. It is not part of
	// the public key or signature this package handles; the versioned
	// stage program implies it.
	OID uint32 = 0x00000002

	// IndexSize, WotsSignatureSize, AuthPathSize and SignatureSize describe
	// a signature: idx || r || WOTS+ signature || authentication path.
	IndexSize         = 4
	WotsSignatureSize = Len * N
	AuthPathSize      = Height * N
	SignatureSize     = IndexSize + N + WotsSignatureSize + AuthPathSize

	// PublicKeySize is root || public seed.
	PublicKeySize = 2 * N

	// Hash domain prefixes, RFC 8391 section 5.1, as toByte(x, 32).
	paddingF         = 0
	paddingH         = 1
	paddingHMsg      = 2
	paddingPRF       = 3
	paddingPRFKeygen = 4

	// Address types, RFC 8391 section 2.5.
	addrTypeOTS      = 0
	addrTypeLTree    = 1
	addrTypeHashTree = 2
)

// PublicKey is an XMSS public key without its OID.
type PublicKey struct {
	Root [N]byte
	Seed [N]byte
}

// Seeds is the private material of a key: the WOTS+ secret seed, the PRF
// key for message randomization and the public seed.
type Seeds struct {
	SKSeed  [N]byte
	SKPRF   [N]byte
	PubSeed [N]byte
}

// Zero overwrites the secret seeds.
func (s *Seeds) Zero() {
	crypto.ZeroBytes(s.SKSeed[:])
	crypto.ZeroBytes(s.SKPRF[:])
}

// address is the 32-byte hash address of RFC 8391 section 2.5: eight
// big-endian words, layer, tree (two words), type, and four type-specific
// words.
type address [8]uint32

func (a *address) setType(t uint32)       { a[3] = t; a[4], a[5], a[6], a[7] = 0, 0, 0, 0 }
func (a *address) setOTS(i uint32)        { a[4] = i }
func (a *address) setChain(i uint32)      { a[5] = i }
func (a *address) setHash(i uint32)       { a[6] = i }
func (a *address) setLTree(i uint32)      { a[4] = i }
func (a *address) setTreeHeight(i uint32) { a[5] = i }
func (a *address) setTreeIndex(i uint32)  { a[6] = i }
func (a *address) setKeyAndMask(i uint32) { a[7] = i }
func (a *address) bytes() (out [32]byte) {
	for i, w := range a {
		binary.BigEndian.PutUint32(out[4*i:], w)
	}
	return out
}

// padding returns toByte(x, N).
func padding(x byte) (out [N]byte) {
	out[N-1] = x
	return out
}

// midstate is a SHA-256 state after absorbing a fixed 64-byte prefix.
// PRF(key, ·) and PRF_keygen(SK_SEED, ·) each start with one constant
// block, so cloning the state saves one compression per call.
type midstate struct {
	state []byte
	h     hash.Hash
}

func newMidstate(prefix []byte) *midstate {
	if len(prefix) != sha256.BlockSize {
		panic("xmss: midstate prefix must be one block")
	}
	h := sha256.New()
	h.Write(prefix)
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return &midstate{state: state, h: h}
}

// sum hashes prefix || tail.
func (m *midstate) sum(tail []byte) (out [N]byte) {
	if err := m.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(m.state); err != nil {
		panic(err)
	}
	m.h.Write(tail)
	m.h.Sum(out[:0])
	return out
}

// hashes carries the per-key midstates. A value is not safe for concurrent
// use; every goroutine builds its own.
type hashes struct {
	pub    *midstate // toByte(3) || SEED
	keygen *midstate // toByte(4) || SK_SEED
}

func newPublicHashes(pubSeed *[N]byte) *hashes {
	var p [2 * N]byte
	p[N-1] = paddingPRF
	copy(p[N:], pubSeed[:])
	return &hashes{pub: newMidstate(p[:])}
}

func newHashes(seeds *Seeds) *hashes {
	hs := newPublicHashes(&seeds.PubSeed)
	var k [2 * N]byte
	k[N-1] = paddingPRFKeygen
	copy(k[N:], seeds.SKSeed[:])
	hs.keygen = newMidstate(k[:])
	crypto.ZeroBytes(k[N:])
	return hs
}

// prfRaw is PRF(key, m) = SHA-256(toByte(3, 32) || key || m) without a
// midstate, for the one-off message randomizer.
func prfRaw(key *[N]byte, m [32]byte) [N]byte {
	var buf [3 * N]byte
	buf[N-1] = paddingPRF
	copy(buf[N:], key[:])
	copy(buf[2*N:], m[:])
	return sha256.Sum256(buf[:])
}

// prf is PRF(SEED, ADRS) = SHA-256(toByte(3, 32) || SEED || ADRS).
func (hs *hashes) prf(a *address) [N]byte {
	ab := a.bytes()
	return hs.pub.sum(ab[:])
}

// prfKeygen is PRF_keygen(SK_SEED, SEED || ADRS) as the reference
// implementation and NIST SP 800-208 define it:
// SHA-256(toByte(4, 32) || SK_SEED || SEED || ADRS).
func (hs *hashes) prfKeygen(pubSeed *[N]byte, a *address) [N]byte {
	var tail [2 * N]byte
	copy(tail[:], pubSeed[:])
	ab := a.bytes()
	copy(tail[N:], ab[:])
	return hs.keygen.sum(tail[:])
}

// f is the keyed, masked chain function F(KEY, M xor BM).
func (hs *hashes) f(a *address, x *[N]byte) [N]byte {
	a.setKeyAndMask(0)
	key := hs.prf(a)
	a.setKeyAndMask(1)
	bm := hs.prf(a)
	var buf [3 * N]byte
	buf[N-1] = paddingF
	copy(buf[N:], key[:])
	for i := range N {
		buf[2*N+i] = x[i] ^ bm[i]
	}
	return sha256.Sum256(buf[:])
}

// h is the keyed, masked node function H(KEY, (L || R) xor (BM0 || BM1)).
func (hs *hashes) h(a *address, left, right *[N]byte) [N]byte {
	a.setKeyAndMask(0)
	key := hs.prf(a)
	a.setKeyAndMask(1)
	bm0 := hs.prf(a)
	a.setKeyAndMask(2)
	bm1 := hs.prf(a)
	var buf [4 * N]byte
	buf[N-1] = paddingH
	copy(buf[N:], key[:])
	for i := range N {
		buf[2*N+i] = left[i] ^ bm0[i]
		buf[3*N+i] = right[i] ^ bm1[i]
	}
	return sha256.Sum256(buf[:])
}

// HashMessage is H_msg(r || root || toByte(idx, 32), msg).
func HashMessage(r, root *[N]byte, index uint32, msg []byte) [N]byte {
	hh := sha256.New()
	p := padding(paddingHMsg)
	hh.Write(p[:])
	hh.Write(r[:])
	hh.Write(root[:])
	var idx [N]byte
	binary.BigEndian.PutUint32(idx[N-4:], index)
	hh.Write(idx[:])
	hh.Write(msg)
	var out [N]byte
	copy(out[:], hh.Sum(nil))
	return out
}

// digits returns the Len1 base-16 message digits and the Len2 checksum
// digits of a 32-byte hashed message (RFC 8391 section 3.1.5).
func digits(m *[N]byte) [Len]uint8 {
	var d [Len]uint8
	sum := 0
	for i, b := range m {
		d[2*i] = b >> 4
		d[2*i+1] = b & 15
		sum += (Steps - int(d[2*i])) + (Steps - int(d[2*i+1]))
	}
	// csum << (8 - ((Len2 * log2(W)) % 8)) spread over ceil(12/8) = 2 bytes.
	d[Len1] = uint8((sum >> 8) & 15)
	d[Len1+1] = uint8((sum >> 4) & 15)
	d[Len1+2] = uint8(sum & 15)
	return d
}

type wotsKey [Len][N]byte

func (k *wotsKey) zero() {
	for i := range k {
		crypto.ZeroBytes(k[i][:])
	}
}

// wotsSecret expands the WOTS+ secret key of the OTS address.
func wotsSecret(hs *hashes, pubSeed *[N]byte, ots *address) wotsKey {
	var sk wotsKey
	a := *ots
	a.setHash(0)
	a.setKeyAndMask(0)
	for i := range uint32(Len) {
		a.setChain(i)
		sk[i] = hs.prfKeygen(pubSeed, &a)
	}
	return sk
}

// chain applies steps start..start+steps-1 of the chain at address a.
func chain(hs *hashes, a *address, x [N]byte, start, steps int) [N]byte {
	for i := start; i < start+steps && i < W; i++ {
		a.setHash(uint32(i))
		x = hs.f(a, &x)
	}
	return x
}

// wotsPublic computes the WOTS+ public key (chain ends) of the OTS address.
func wotsPublic(hs *hashes, seeds *Seeds, ots *address) wotsKey {
	pk := wotsSecret(hs, &seeds.PubSeed, ots)
	a := *ots
	for i := range uint32(Len) {
		a.setChain(i)
		pk[i] = chain(hs, &a, pk[i], 0, Steps)
	}
	return pk
}

// wotsSign signs the hashed message with the OTS address's key.
func wotsSign(hs *hashes, seeds *Seeds, ots *address, mhash *[N]byte) wotsKey {
	sig := wotsSecret(hs, &seeds.PubSeed, ots)
	d := digits(mhash)
	a := *ots
	for i := range uint32(Len) {
		a.setChain(i)
		sig[i] = chain(hs, &a, sig[i], 0, int(d[i]))
	}
	return sig
}

// wotsPublicFromSignature completes the chains of a signature.
func wotsPublicFromSignature(hs *hashes, ots *address, mhash *[N]byte, sig []byte) wotsKey {
	var pk wotsKey
	d := digits(mhash)
	a := *ots
	for i := range uint32(Len) {
		a.setChain(i)
		var x [N]byte
		copy(x[:], sig[int(i)*N:(int(i)+1)*N])
		pk[i] = chain(hs, &a, x, int(d[i]), Steps-int(d[i]))
	}
	return pk
}

// ltree compresses a WOTS+ public key to a leaf (RFC 8391 section 4.1.5).
func ltree(hs *hashes, lt *address, pk *wotsKey) [N]byte {
	a := *lt
	l := Len
	height := uint32(0)
	for l > 1 {
		a.setTreeHeight(height)
		for i := 0; i < l/2; i++ {
			a.setTreeIndex(uint32(i))
			pk[i] = hs.h(&a, &pk[2*i], &pk[2*i+1])
		}
		if l&1 == 1 {
			pk[l/2] = pk[l-1]
			l = l/2 + 1
		} else {
			l /= 2
		}
		height++
	}
	return pk[0]
}

// leaf computes leaf index of the tree rooted at layer 0, tree 0.
func leaf(hs *hashes, seeds *Seeds, index uint32) [N]byte {
	var ots, lt address
	ots.setType(addrTypeOTS)
	ots.setOTS(index)
	lt.setType(addrTypeLTree)
	lt.setLTree(index)
	pk := wotsPublic(hs, seeds, &ots)
	out := ltree(hs, &lt, &pk)
	pk.zero()
	return out
}

// Leaf returns one leaf of the tree, for tests and spot checks.
func Leaf(seeds *Seeds, index uint32) ([N]byte, error) {
	if index >= Leaves {
		return [N]byte{}, fmt.Errorf("xmss leaf index %d out of range", index)
	}
	return leaf(newHashes(seeds), seeds, index), nil
}

// Tree is the public hash tree: every node of every level, so an
// authentication path is a lookup. It is about 4 MiB and reconstructible
// from the seeds.
type Tree struct {
	height int
	levels [][][N]byte // levels[h][i]
}

// GenerateTree builds the full tree from the seeds, leaves in parallel.
func GenerateTree(seeds *Seeds) *Tree {
	return generateTree(seeds, Height)
}

func generateTree(seeds *Seeds, height int) *Tree {
	t := &Tree{height: height, levels: make([][][N]byte, height+1)}
	for lvl := 0; lvl <= height; lvl++ {
		t.levels[lvl] = make([][N]byte, 1<<(height-lvl))
	}
	leaves := uint32(1) << height
	workers := runtime.NumCPU()
	if int(leaves) < workers {
		workers = int(leaves)
	}
	var next uint32
	var mu sync.Mutex
	var wg sync.WaitGroup
	const batch = 32
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hs := newHashes(seeds)
			for {
				mu.Lock()
				start := next
				next += batch
				mu.Unlock()
				if start >= leaves {
					return
				}
				end := min(start+batch, leaves)
				for i := start; i < end; i++ {
					t.levels[0][i] = leaf(hs, seeds, i)
				}
			}
		}()
	}
	wg.Wait()
	hs := newPublicHashes(&seeds.PubSeed)
	var a address
	a.setType(addrTypeHashTree)
	for lvl := 1; lvl <= height; lvl++ {
		a.setTreeHeight(uint32(lvl - 1))
		for i := range t.levels[lvl] {
			a.setTreeIndex(uint32(i))
			t.levels[lvl][i] = hs.h(&a, &t.levels[lvl-1][2*i], &t.levels[lvl-1][2*i+1])
		}
	}
	return t
}

// Root returns the tree root.
func (t *Tree) Root() [N]byte { return t.levels[t.height][0] }

// AuthPath returns the siblings of leaf index from the leaf level up.
func (t *Tree) AuthPath(index uint32) []byte {
	out := make([]byte, 0, t.height*N)
	for lvl := 0; lvl < t.height; lvl++ {
		sib := t.levels[lvl][(index>>lvl)^1]
		out = append(out, sib[:]...)
	}
	return out
}

// Sign signs msg with leaf index of the tree. The caller chooses the index
// and must not reuse one; this package does not track it. The signature is
// idx || r || WOTS+ signature || authentication path.
func Sign(seeds *Seeds, tree *Tree, index uint32, msg []byte) ([]byte, error) {
	if tree == nil || tree.height != Height {
		return nil, fmt.Errorf("xmss tree has height %d, want %d", treeHeight(tree), Height)
	}
	return sign(seeds, tree, index, msg)
}

func treeHeight(t *Tree) int {
	if t == nil {
		return -1
	}
	return t.height
}

func sign(seeds *Seeds, tree *Tree, index uint32, msg []byte) ([]byte, error) {
	if index >= uint32(1)<<tree.height {
		return nil, fmt.Errorf("xmss index %d out of range", index)
	}
	var idx32 [32]byte
	binary.BigEndian.PutUint32(idx32[28:], index)
	r := prfRaw(&seeds.SKPRF, idx32)
	root := tree.Root()
	mhash := HashMessage(&r, &root, index, msg)
	var ots address
	ots.setType(addrTypeOTS)
	ots.setOTS(index)
	ws := wotsSign(newHashes(seeds), seeds, &ots, &mhash)
	sig := make([]byte, 0, IndexSize+N+WotsSignatureSize+tree.height*N)
	sig = append(sig, idx32[28:]...)
	sig = append(sig, r[:]...)
	for i := range ws {
		sig = append(sig, ws[i][:]...)
	}
	ws.zero()
	sig = append(sig, tree.AuthPath(index)...)
	return sig, nil
}

// Index returns the leaf index a signature names.
func Index(sig []byte) (uint32, error) {
	if len(sig) < IndexSize {
		return 0, fmt.Errorf("xmss signature is %d bytes", len(sig))
	}
	return binary.BigEndian.Uint32(sig[:IndexSize]), nil
}

// Verify checks sig over msg against pk.
func Verify(pk *PublicKey, msg, sig []byte) error {
	return verify(pk, msg, sig, Height)
}

func verify(pk *PublicKey, msg, sig []byte, height int) error {
	want := IndexSize + N + WotsSignatureSize + height*N
	if len(sig) != want {
		return fmt.Errorf("xmss signature is %d bytes, want %d", len(sig), want)
	}
	index := binary.BigEndian.Uint32(sig[:IndexSize])
	if index >= uint32(1)<<height {
		return fmt.Errorf("xmss index %d out of range", index)
	}
	var r [N]byte
	copy(r[:], sig[IndexSize:IndexSize+N])
	mhash := HashMessage(&r, &pk.Root, index, msg)
	wots := sig[IndexSize+N : IndexSize+N+WotsSignatureSize]
	auth := sig[IndexSize+N+WotsSignatureSize:]

	var ots, lt, node address
	ots.setType(addrTypeOTS)
	ots.setOTS(index)
	lt.setType(addrTypeLTree)
	lt.setLTree(index)
	node.setType(addrTypeHashTree)

	hs := newPublicHashes(&pk.Seed)
	wpk := wotsPublicFromSignature(hs, &ots, &mhash, wots)
	cur := ltree(hs, &lt, &wpk)
	offset := index
	for lvl := 0; lvl < height; lvl++ {
		node.setTreeHeight(uint32(lvl))
		node.setTreeIndex(offset >> 1)
		var sib [N]byte
		copy(sib[:], auth[lvl*N:(lvl+1)*N])
		if offset&1 == 0 {
			cur = hs.h(&node, &cur, &sib)
		} else {
			cur = hs.h(&node, &sib, &cur)
		}
		offset >>= 1
	}
	if subtle.ConstantTimeCompare(cur[:], pk.Root[:]) != 1 {
		return fmt.Errorf("xmss signature does not verify")
	}
	return nil
}

// MaxVerifySteps is the most chain steps a verification performs: every
// message digit 0 (64 x 15 steps) gives checksum 960 = 0x3c0, whose digits
// 3, 12 and 0 cost 12 + 3 + 15 more.
const MaxVerifySteps = Len1*Steps + 12 + 3 + 15

// VerifySteps returns the number of chain steps Verify performs for sig
// over msg under pk: the sum over the 67 chains of (15 - digit) of the
// hashed message. It does not verify the signature.
func VerifySteps(pk *PublicKey, msg, sig []byte) (int, error) {
	if len(sig) < IndexSize+N {
		return 0, fmt.Errorf("xmss signature is %d bytes", len(sig))
	}
	index := binary.BigEndian.Uint32(sig[:IndexSize])
	var r [N]byte
	copy(r[:], sig[IndexSize:IndexSize+N])
	mhash := HashMessage(&r, &pk.Root, index, msg)
	d := digits(&mhash)
	steps := 0
	for _, v := range d {
		steps += Steps - int(v)
	}
	return steps, nil
}
