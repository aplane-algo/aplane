// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package wotsc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func testKey(tag byte) *SigningKey {
	var skSeed, skPrf, pkSeed [N]byte
	for i := range N {
		skSeed[i], skPrf[i], pkSeed[i] = tag+byte(i), tag^byte(3*i), tag+byte(5*i)
	}
	return NewSigningKey(&skSeed, &skPrf, &pkSeed)
}

func testMessage(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

func TestSizes(t *testing.T) {
	if SignatureSize != 628 {
		t.Fatalf("SignatureSize = %d, want 628", SignatureSize)
	}
	if VerifyHashCalls != 248 {
		t.Fatalf("VerifyHashCalls = %d, want 248", VerifyHashCalls)
	}
	if TargetSum != Len*(W-1)/2 {
		t.Fatalf("TargetSum %d is not the most likely sum", TargetSum)
	}
}

// The vectors come from tools/wotscoracle, a second implementation that shares
// no code with this package.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		SKSeed string `json:"sk_seed"`
		SKPrf  string `json:"sk_prf"`
		PKSeed string `json:"pk_seed"`
		Root   string `json:"root"`
		Cases  []struct {
			Leaf      uint32 `json:"leaf"`
			Message   string `json:"message"`
			Counter   uint32 `json:"counter"`
			Signature string `json:"signature"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no vectors")
	}
	seed := func(s string) *[N]byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != N {
			t.Fatalf("bad seed %q", s)
		}
		return (*[N]byte)(b)
	}
	sk := NewSigningKey(seed(file.SKSeed), seed(file.SKPrf), seed(file.PKSeed))
	if got := hex.EncodeToString(sk.Public.Root[:]); got != file.Root {
		t.Fatalf("root = %s, want %s", got, file.Root)
	}
	for _, c := range file.Cases {
		msg, err := hex.DecodeString(c.Message)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(c.Signature)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sk.Sign(c.Leaf, msg)
		if err != nil {
			t.Fatalf("leaf %d: %v", c.Leaf, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("leaf %d: signature differs from the vector", c.Leaf)
		}
		if _, _, ctr, _ := sk.grind(c.Leaf, msg, GrindLimit); ctr != c.Counter {
			t.Fatalf("leaf %d: counter %d, want %d", c.Leaf, ctr, c.Counter)
		}
		if err := Verify(&sk.Public, msg, want); err != nil {
			t.Fatalf("leaf %d: vector doesn't verify: %v", c.Leaf, err)
		}
	}
}

func TestSignVerifyEveryLeaf(t *testing.T) {
	sk := testKey(1)
	for leaf := range uint32(Leaves) {
		msg := testMessage(fmt.Sprintf("leaf %d", leaf))
		sig, err := sk.Sign(leaf, msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != SignatureSize {
			t.Fatalf("signature is %d bytes", len(sig))
		}
		if err := Verify(&sk.Public, msg, sig); err != nil {
			t.Fatalf("leaf %d: %v", leaf, err)
		}
	}
}

func TestSigningIsDeterministic(t *testing.T) {
	sk := testKey(2)
	msg := testMessage("retry")
	first, err := sk.Sign(9, msg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sk.Sign(9, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("the same leaf and message gave a different signature")
	}
	third, err := testKey(2).Sign(9, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatal("rebuilding the key from the same seeds gave a different signature")
	}
}

func TestVerifyRejects(t *testing.T) {
	sk := testKey(3)
	msg := testMessage("message")
	const leaf = 21
	sig, err := sk.Sign(leaf, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&sk.Public, msg, sig); err != nil {
		t.Fatal(err)
	}
	rejected := func(t *testing.T, msg, sig []byte) {
		t.Helper()
		if Verify(&sk.Public, msg, sig) == nil {
			t.Fatal("accepted")
		}
	}
	flipped := func(at int) []byte {
		s := bytes.Clone(sig)
		s[at] ^= 1
		return s
	}
	t.Run("every byte", func(t *testing.T) {
		for at := range sig {
			rejected(t, msg, flipped(at))
		}
	})
	t.Run("other message", func(t *testing.T) {
		rejected(t, testMessage("other"), sig)
	})
	t.Run("sizes", func(t *testing.T) {
		rejected(t, msg, sig[:len(sig)-1])
		rejected(t, msg, append(bytes.Clone(sig), 0))
		rejected(t, msg[:31], sig)
		rejected(t, append(bytes.Clone(msg), 0), sig)
	})
	t.Run("leaf out of range", func(t *testing.T) {
		s := bytes.Clone(sig)
		s[3] = Leaves
		rejected(t, msg, s)
		s[3], s[0] = byte(leaf), 1
		rejected(t, msg, s)
	})
	t.Run("other key", func(t *testing.T) {
		if Verify(&testKey(4).Public, msg, sig) == nil {
			t.Fatal("accepted under another key")
		}
	})
}

// honestSignature builds a signature for any randomizer, whatever its digit
// sum. Only the sum check separates it from a valid one.
func honestSignature(sk *SigningKey, leaf uint32, msg []byte, r *[N]byte) []byte {
	digits, _ := Digits(&sk.Public, r, leaf, msg)
	hs := newHasher(&sk.Public.Seed)
	defer hs.zero()
	sig := binary.BigEndian.AppendUint32(nil, leaf)
	sig = append(sig, r[:]...)
	for j := uint32(0); j < Len; j++ {
		value := hs.chain(hs.chainSecret(&sk.SKSeed, leaf, j), 0, uint32(digits[j]), leaf, j)
		sig = append(sig, value[:]...)
	}
	for node := Leaves + leaf; node > 1; node /= 2 {
		sig = append(sig, sk.nodes[node^1][:]...)
	}
	return sig
}

// Every chain in these signatures reaches the public key, so nothing but the
// sum check rejects them. Without it, a digest of high digits would forge from
// any signature, because anyone can hash a revealed value further along its
// chain. Both directions are covered.
func TestWrongDigitSumIsRejected(t *testing.T) {
	sk := testKey(5)
	msg := testMessage("signed")
	const leaf = 7
	seen := map[bool]bool{}
	for c := 0; len(seen) < 2; c++ {
		var r [N]byte
		copy(r[:], testMessage(fmt.Sprintf("r %d", c)))
		_, sum := Digits(&sk.Public, &r, leaf, msg)
		if sum == TargetSum {
			continue
		}
		seen[sum > TargetSum] = true
		if err := Verify(&sk.Public, msg, honestSignature(sk, leaf, msg, &r)); !errors.Is(err, ErrVerify) {
			t.Fatalf("digit sum %d: %v", sum, err)
		}
	}

	// The same construction verifies once the sum is right, so the rejections
	// above come from the sum and not from a broken signature.
	r, _, _, err := sk.grind(leaf, msg, GrindLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&sk.Public, msg, honestSignature(sk, leaf, msg, &r)); err != nil {
		t.Fatalf("digit sum %d: %v", TargetSum, err)
	}
}

func TestGrindLimitStopsTheSearch(t *testing.T) {
	sk := testKey(13)
	msg := testMessage("limit")
	_, _, ctr, err := sk.grind(0, msg, GrindLimit)
	if err != nil {
		t.Fatal(err)
	}
	if ctr == 0 {
		t.Fatal("the first counter qualified, so this message tests nothing")
	}
	if _, _, _, err := sk.grind(0, msg, ctr); !errors.Is(err, ErrGrindLimit) {
		t.Fatalf("a limit below the first hit: %v", err)
	}
	if _, _, got, err := sk.grind(0, msg, ctr+1); err != nil || got != ctr {
		t.Fatalf("a limit at the first hit: counter %d, %v", got, err)
	}
}

func TestSignArgumentErrors(t *testing.T) {
	sk := testKey(6)
	if _, err := sk.Sign(Leaves, testMessage("m")); !errors.Is(err, ErrLeafIndex) {
		t.Fatalf("leaf: %v", err)
	}
	if _, err := sk.Sign(0, []byte("short")); !errors.Is(err, ErrMessageSize) {
		t.Fatalf("message: %v", err)
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	sk := testKey(7)
	pk, err := ParsePublicKey(sk.Public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if *pk != sk.Public {
		t.Fatal("public key changed in the round trip")
	}
	if _, err := ParsePublicKey(make([]byte, PublicKeySize-1)); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short key: %v", err)
	}
}

func TestZero(t *testing.T) {
	sk := testKey(8)
	sk.Zero()
	if sk.SKSeed != ([N]byte{}) || sk.SKPrf != ([N]byte{}) {
		t.Fatal("seeds not erased")
	}
}

// The search stays far from its limit. This pins the claim in the GrindLimit
// comment against a sample, not a proof.
func TestGrindStaysBelowLimit(t *testing.T) {
	sk := testKey(9)
	total, worst := 0, uint32(0)
	const samples = 2000
	for i := range samples {
		_, digits, ctr, err := sk.grind(uint32(i%Leaves), testMessage(fmt.Sprintf("grind %d", i)), GrindLimit)
		if err != nil {
			t.Fatal(err)
		}
		sum := 0
		for _, d := range digits {
			sum += int(d)
		}
		if sum != TargetSum {
			t.Fatalf("grind returned digit sum %d", sum)
		}
		total += int(ctr) + 1
		worst = max(worst, ctr)
	}
	if mean := total / samples; mean < 50 || mean > 85 {
		t.Fatalf("mean tries %d, expected about 66", mean)
	}
	if worst >= GrindLimit/2 {
		t.Fatalf("worst counter %d is near the limit", worst)
	}
}

func BenchmarkNewSigningKey(b *testing.B) {
	for b.Loop() {
		testKey(10)
	}
}

func BenchmarkSign(b *testing.B) {
	sk := testKey(11)
	msg := testMessage("benchmark")
	for b.Loop() {
		if _, err := sk.Sign(3, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	sk := testKey(12)
	msg := testMessage("benchmark")
	sig, err := sk.Sign(3, msg)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if err := Verify(&sk.Public, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}
