// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package xmss

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/racetest"
	"golang.org/x/crypto/sha3"
)

type vectorCase struct {
	Index     uint32 `json:"index"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type vectorFile struct {
	ParamSet string       `json:"param_set"`
	Oracle   string       `json:"oracle"`
	SKSeed   string       `json:"sk_seed"`
	SKPRF    string       `json:"sk_prf"`
	PubSeed  string       `json:"pub_seed"`
	Root     string       `json:"root"`
	Cases    []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.ParamSet != "XMSS-SHA2_16_256" || len(v.Cases) == 0 {
		t.Fatalf("unexpected vector file: %s, %d cases", v.ParamSet, len(v.Cases))
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorSeeds(t *testing.T, v vectorFile) *Seeds {
	t.Helper()
	var s Seeds
	copy(s.SKSeed[:], mustHex(t, v.SKSeed))
	copy(s.SKPRF[:], mustHex(t, v.SKPRF))
	copy(s.PubSeed[:], mustHex(t, v.PubSeed))
	return &s
}

var (
	fullTreeOnce sync.Once
	fullTree     *Tree
)

// vectorTree builds the vector key's full tree once per test binary.
func vectorTree(t *testing.T, seeds *Seeds) *Tree {
	t.Helper()
	racetest.SkipFullTree(t)
	fullTreeOnce.Do(func() { fullTree = GenerateTree(seeds) })
	return fullTree
}

func vectorPublicKey(t *testing.T, v vectorFile) *PublicKey {
	t.Helper()
	var pk PublicKey
	copy(pk.Root[:], mustHex(t, v.Root))
	copy(pk.Seed[:], mustHex(t, v.PubSeed))
	return &pk
}

// Every oracle signature verifies, and our signature at the same index over
// the same message is byte-identical (r is deterministic in the index).
func TestVectorsMatchOracle(t *testing.T) {
	v := loadVectors(t)
	seeds := vectorSeeds(t, v)
	tree := vectorTree(t, seeds)
	root := tree.Root()
	if hex.EncodeToString(root[:]) != v.Root {
		t.Fatalf("root %x, oracle %s", root, v.Root)
	}
	pk := vectorPublicKey(t, v)
	for _, c := range v.Cases {
		msg := mustHex(t, c.Message)
		theirs := mustHex(t, c.Signature)
		if len(theirs) != SignatureSize {
			t.Fatalf("case %d: oracle signature is %d bytes", c.Index, len(theirs))
		}
		if err := Verify(pk, msg, theirs); err != nil {
			t.Fatalf("case %d: oracle signature rejected: %v", c.Index, err)
		}
		ours, err := Sign(seeds, tree, c.Index, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ours, theirs) {
			t.Fatalf("case %d: our signature differs from the oracle's", c.Index)
		}
		if idx, err := Index(ours); err != nil || idx != c.Index {
			t.Fatalf("Index() = %d, %v; want %d", idx, err, c.Index)
		}
	}
}

// refHash is the XMSS reference implementation's test-vector digest: the
// first ten bytes of SHAKE128.
func refHash(in []byte) string {
	var out [10]byte
	h := sha3.NewShake128()
	h.Write(in)
	if _, err := h.Read(out[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(out[:])
}

// The XMSS reference implementation's own SHA-256 vector (test/vectors,
// pinned by go-xmssmt's TestXMSS): OID 1, XMSS-SHA2_10_256, seeds 0..95,
// message {37} at index 2^9. The only difference from our parameter set is
// the height, which the internals take as a parameter, so this ties every
// hash, address and encoding to the C reference rather than to the oracle.
func TestReferenceImplementationVector(t *testing.T) {
	const height = 10
	v := loadVectors(t)
	seeds := vectorSeeds(t, v)
	tree := generateTree(seeds, height)
	root := tree.Root()
	if got := refHash(append(append([]byte{}, root[:]...), seeds.PubSeed[:]...)); got != "7de72d192121f414d4bb" {
		t.Fatalf("public key digest %s, want 7de72d192121f414d4bb", got)
	}
	sig, err := sign(seeds, tree, 1<<(height-1), []byte{37})
	if err != nil {
		t.Fatal(err)
	}
	if got := refHash(sig); got != "8b6cb278d50a3694ca38" {
		t.Fatalf("signature digest %s, want 8b6cb278d50a3694ca38", got)
	}
	pk := &PublicKey{Root: root, Seed: seeds.PubSeed}
	if err := verify(pk, []byte{37}, sig, height); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	v := loadVectors(t)
	pk := vectorPublicKey(t, v)
	c := v.Cases[0]
	msg := mustHex(t, c.Message)
	good := mustHex(t, c.Signature)
	if err := Verify(pk, msg, good); err != nil {
		t.Fatal(err)
	}
	flip := func(off int) []byte {
		s := append([]byte{}, good...)
		s[off] ^= 1
		return s
	}
	cases := []struct {
		name string
		pk   *PublicKey
		msg  []byte
		sig  []byte
	}{
		{"index changed", pk, msg, flip(IndexSize - 1)},
		{"index out of range", pk, msg, func() []byte {
			s := append([]byte{}, good...)
			binary.BigEndian.PutUint32(s[:4], Leaves)
			return s
		}()},
		{"r flipped", pk, msg, flip(IndexSize)},
		{"first wots byte flipped", pk, msg, flip(IndexSize + N)},
		{"last wots byte flipped", pk, msg, flip(IndexSize + N + WotsSignatureSize - 1)},
		{"first auth byte flipped", pk, msg, flip(IndexSize + N + WotsSignatureSize)},
		{"last auth byte flipped", pk, msg, flip(SignatureSize - 1)},
		{"truncated", pk, msg, good[:SignatureSize-1]},
		{"extended", pk, msg, append(append([]byte{}, good...), 0)},
		{"empty", pk, msg, nil},
		{"message changed", pk, append(append([]byte{}, msg...), 1), good},
		{"root changed", &PublicKey{Root: func() [N]byte { r := pk.Root; r[0] ^= 1; return r }(), Seed: pk.Seed}, msg, good},
		{"seed changed", &PublicKey{Root: pk.Root, Seed: func() [N]byte { s := pk.Seed; s[0] ^= 1; return s }()}, msg, good},
	}
	for _, tc := range cases {
		if err := Verify(tc.pk, tc.msg, tc.sig); err == nil {
			t.Errorf("%s: verified", tc.name)
		}
	}
}

func TestSignRejectsOutOfRangeIndex(t *testing.T) {
	v := loadVectors(t)
	seeds := vectorSeeds(t, v)
	tree := vectorTree(t, seeds)
	if _, err := Sign(seeds, tree, Leaves, []byte("x")); err == nil {
		t.Fatal("signed with index Leaves")
	}
	if _, err := Sign(seeds, nil, 0, []byte("x")); err == nil {
		t.Fatal("signed with a nil tree")
	}
}

func randomSeeds(t *testing.T) *Seeds {
	t.Helper()
	var s Seeds
	for _, b := range [][]byte{s.SKSeed[:], s.SKPRF[:], s.PubSeed[:]} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	return &s
}

// A small tree exercises every leaf, the checksum extremes and
// cross-message rejection without the full tree's generation time.
func TestSmallTreeRoundTrip(t *testing.T) {
	const height = 4
	seeds := randomSeeds(t)
	tree := generateTree(seeds, height)
	root := tree.Root()
	pk := &PublicKey{Root: root, Seed: seeds.PubSeed}
	messages := [][]byte{
		bytes.Repeat([]byte{0x00}, 32), // every digit 0: checksum 960
		bytes.Repeat([]byte{0xff}, 32), // every digit 15: checksum 0
		[]byte("a message of some other length"),
		{},
	}
	for idx := uint32(0); idx < 1<<height; idx++ {
		for _, msg := range messages {
			sig, err := sign(seeds, tree, idx, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := verify(pk, msg, sig, height); err != nil {
				t.Fatalf("leaf %d: %v", idx, err)
			}
			if err := verify(pk, append([]byte{1}, msg...), sig, height); err == nil {
				t.Fatalf("leaf %d: verified a different message", idx)
			}
		}
		if got, err := Leaf(seeds, idx); err != nil || got != tree.levels[0][idx] {
			t.Fatalf("Leaf(%d) = %x, %v; want %x", idx, got, err, tree.levels[0][idx])
		}
	}
	if _, err := sign(seeds, tree, 1<<height, nil); err == nil {
		t.Fatal("signed with an out-of-range index on the small tree")
	}
}

func TestSizes(t *testing.T) {
	if SignatureSize != 2692 || WotsSignatureSize != 2144 || AuthPathSize != 512 || PublicKeySize != 64 {
		t.Fatalf("sizes %d %d %d %d", SignatureSize, WotsSignatureSize, AuthPathSize, PublicKeySize)
	}
	if Leaves != 65536 || Len != 67 {
		t.Fatalf("Leaves %d Len %d", Leaves, Len)
	}
}

func BenchmarkLeaf(b *testing.B) {
	var s Seeds
	hs := newHashes(&s)
	for i := range b.N {
		leaf(hs, &s, uint32(i))
	}
}

func BenchmarkVerify(b *testing.B) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		b.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		b.Fatal(err)
	}
	var pk PublicKey
	root, _ := hex.DecodeString(v.Root)
	seed, _ := hex.DecodeString(v.PubSeed)
	copy(pk.Root[:], root)
	copy(pk.Seed[:], seed)
	msg, _ := hex.DecodeString(v.Cases[0].Message)
	sig, _ := hex.DecodeString(v.Cases[0].Signature)
	b.ResetTimer()
	for range b.N {
		if err := Verify(&pk, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateTree(b *testing.B) {
	var s Seeds
	for range b.N {
		GenerateTree(&s)
	}
}

func TestSeedsZeroClearsSecrets(t *testing.T) {
	s := randomSeeds(t)
	pub := s.PubSeed
	s.Zero()
	if s.SKSeed != [N]byte{} || s.SKPRF != [N]byte{} {
		t.Fatal("Zero left secret seed material")
	}
	if s.PubSeed != pub {
		t.Fatal("Zero cleared the public seed")
	}
}

func TestVerifySteps(t *testing.T) {
	if MaxVerifySteps != 990 {
		t.Fatalf("MaxVerifySteps = %d", MaxVerifySteps)
	}
	v := loadVectors(t)
	pk := vectorPublicKey(t, v)
	for _, c := range v.Cases {
		sig := mustHex(t, c.Signature)
		steps, err := VerifySteps(pk, mustHex(t, c.Message), sig)
		if err != nil || steps < 0 || steps > MaxVerifySteps {
			t.Fatalf("case %d: steps %d, %v", c.Index, steps, err)
		}
		// Recompute from the digits directly.
		var r [N]byte
		copy(r[:], sig[IndexSize:IndexSize+N])
		mhash := HashMessage(&r, &pk.Root, c.Index, mustHex(t, c.Message))
		want := 0
		for _, d := range digits(&mhash) {
			want += Steps - int(d)
		}
		if steps != want {
			t.Fatalf("case %d: steps %d, want %d", c.Index, steps, want)
		}
	}
	if _, err := VerifySteps(pk, nil, []byte{1}); err == nil {
		t.Fatal("short signature accepted")
	}
}

// Erasing the hashes leaves no trace of the keyed midstate, which is as
// secret as SK_SEED, in either the serialized state or the hash object.
func TestHashesZeroErasesSecretState(t *testing.T) {
	var s Seeds
	if _, err := rand.Read(s.SKSeed[:]); err != nil {
		t.Fatal(err)
	}
	hs := newHashes(&s)
	keyed := append([]byte(nil), hs.keygen.state...)
	if bytes.Equal(keyed, freshState) {
		t.Fatal("keyed midstate equals the empty state")
	}
	var a address
	hs.prfKeygen(&s.PubSeed, &a) // leave a digest in the hash object
	hs.zero()
	for _, m := range []*midstate{hs.keygen, hs.pub} {
		for _, b := range m.state {
			if b != 0 {
				t.Fatal("serialized midstate not erased")
			}
		}
		got, err := m.h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, freshState) {
			t.Fatal("hash object still carries state")
		}
	}
	if bytes.Equal(keyed, hs.keygen.state) {
		t.Fatal("state unchanged")
	}
}

// VerifySteps of a signature is 45 + 255a + 15b for the hexadecimal digits
// a, b of its checksum, so a checksum of at most 511 means at most 525
// steps and 512 already means 555. Checked over every reachable checksum.
func TestChecksumStepBound(t *testing.T) {
	stepsFor := func(sum int) int {
		// A digest whose message digits sum to the checksum: the first
		// sum/15 digits are 0, one digit is the remainder, the rest 15.
		var m [N]byte
		d := make([]uint8, Len1)
		for i := range d {
			d[i] = 15
		}
		rem := sum
		for i := 0; i < Len1 && rem > 0; i++ {
			take := min(rem, 15)
			d[i] = uint8(15 - take)
			rem -= take
		}
		for i := 0; i < N; i++ {
			m[i] = d[2*i]<<4 | d[2*i+1]
		}
		if Checksum(&m) != sum {
			t.Fatalf("constructed digest has checksum %d, want %d", Checksum(&m), sum)
		}
		steps := 0
		for _, v := range digits(&m) {
			steps += Steps - int(v)
		}
		return steps
	}
	maxBelow, maxAt := 0, 0
	for sum := 0; sum <= Len1*Steps; sum++ {
		a, b := sum>>8, (sum>>4)&15
		if got := stepsFor(sum); got != 45+255*a+15*b {
			t.Fatalf("checksum %d: steps %d, formula %d", sum, got, 45+255*a+15*b)
		}
		if sum <= MaxBoundedChecksum {
			maxBelow = max(maxBelow, stepsFor(sum))
		}
		if sum == MaxBoundedChecksum+1 {
			maxAt = stepsFor(sum)
		}
	}
	if maxBelow != MaxBoundedVerifySteps || maxAt != 555 {
		t.Fatalf("max steps within the cap %d (want %d), at 512: %d (want 555)", maxBelow, MaxBoundedVerifySteps, maxAt)
	}
}

// SignBounded meets the cap, verifies as an ordinary RFC signature, is
// deterministic, equals Sign when counter 0 already qualifies, and
// otherwise differs only in the randomizer it chose.
func TestSignBoundedMeetsTheCap(t *testing.T) {
	var seeds Seeds
	for i := range seeds.SKSeed {
		seeds.SKSeed[i], seeds.SKPRF[i], seeds.PubSeed[i] = byte(i), byte(i+1), byte(i+2)
	}
	const height = 8
	tree := generateTree(&seeds, height)
	pk := &PublicKey{Root: tree.Root(), Seed: seeds.PubSeed}
	searched, plain := 0, 0
	for index := uint32(0); index < 1<<height; index++ {
		msg := []byte(fmt.Sprintf("message %d", index))
		rfc, err := sign(&seeds, tree, index, msg)
		if err != nil {
			t.Fatal(err)
		}
		bounded, err := signBounded(&seeds, tree, index, msg, MaxBoundedChecksum)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(pk, msg, bounded, height); err != nil {
			t.Fatalf("index %d: bounded signature rejected: %v", index, err)
		}
		sum, err := MessageChecksum(pk, msg, bounded)
		if err != nil {
			t.Fatal(err)
		}
		if sum > MaxBoundedChecksum {
			t.Fatalf("index %d: checksum %d above the cap", index, sum)
		}
		again, err := signBounded(&seeds, tree, index, msg, MaxBoundedChecksum)
		if err != nil || !bytes.Equal(again, bounded) {
			t.Fatalf("index %d: bounded signing is not deterministic", index)
		}
		rfcSum, _ := MessageChecksum(pk, msg, rfc)
		if rfcSum <= MaxBoundedChecksum {
			plain++
			if !bytes.Equal(rfc, bounded) {
				t.Fatalf("index %d: counter 0 qualified but the signature differs from Sign's", index)
			}
		} else {
			searched++
			if bytes.Equal(rfc[IndexSize:IndexSize+N], bounded[IndexSize:IndexSize+N]) {
				t.Fatalf("index %d: searched signature kept the RFC randomizer", index)
			}
		}
	}
	if searched == 0 || plain == 0 {
		t.Fatalf("searched %d, plain %d: the sample did not exercise both paths", searched, plain)
	}
	t.Logf("%d of %d signatures needed a search", searched, 1<<height)
	if _, err := signBounded(&seeds, tree, 0, []byte("x"), -1); !errors.Is(err, ErrRandomizerSearchExhausted) {
		t.Fatalf("impossible cap: %v", err)
	}
}
