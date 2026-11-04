// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/avmsim"
)

const (
	offsetR      = 4
	offsetChains = offsetR + wotsc.N
	offsetAuth   = offsetChains + wotsc.Len*wotsc.N
)

// verifierRig runs the TEAL verifier in the interpreter against the Go
// primitive for the same key. The Ed25519 and Falcon opcodes are stubbed: the
// property under test is the WOTS+C leg.
type verifierRig struct {
	t        *testing.T
	sk       *wotsc.SigningKey
	keys     *PublicKeys
	prog     *avmsim.Program
	hookDeny bool
	hooked   int
	// lastEqual is the operand pair of the most recent == the program ran.
	lastEqual [2]avmsim.Value
}

func newVerifierRig(t *testing.T, tag byte) *verifierRig {
	t.Helper()
	var skSeed, skPrf, pkSeed [wotsc.N]byte
	for i := range skSeed {
		skSeed[i], skPrf[i], pkSeed[i] = tag+byte(i), tag^byte(3*i), tag+byte(5*i)
	}
	sk := wotsc.NewSigningKey(&skSeed, &skPrf, &pkSeed)
	keys := &PublicKeys{Seed: sk.Public.Seed, Root: sk.Public.Root}
	for i := range keys.Ed25519 {
		keys.Ed25519[i] = tag ^ byte(i)
	}
	for i := range keys.Falcon {
		keys.Falcon[i] = tag + byte(i%251)
	}
	r := &verifierRig{t: t, sk: sk, keys: keys}
	r.assemble(TEALSource(keys))
	return r
}

func (r *verifierRig) assemble(source string) {
	r.t.Helper()
	prog, err := avmsim.Assemble(source)
	if err != nil {
		r.t.Fatalf("assemble: %v", err)
	}
	r.prog = prog
}

func defaultTxn(txid []byte) avmsim.Txn {
	return avmsim.Txn{
		TxID:       txid,
		Sender:     bytes.Repeat([]byte{1}, 32),
		RekeyTo:    bytes.Repeat([]byte{2}, 32),
		FirstValid: 1000, LastValid: 1100,
		CloseRemainderTo: make([]byte, 32),
	}
}

func (r *verifierRig) runTxn(txn avmsim.Txn, sig []byte) bool {
	r.t.Helper()
	args := [][]byte{slices.Clone(sig), []byte("ed25519 signature"), []byte("falcon signature")}
	ok, err := r.prog.Run(txn, args, avmsim.Hooks{
		Ed25519: func(_, _, _ []byte) bool { r.hooked++; return !r.hookDeny },
		Falcon:  func(_, _, _ []byte) bool { r.hooked++; return !r.hookDeny },
		Equal:   func(a, b avmsim.Value) { r.lastEqual = [2]avmsim.Value{a, b} },
	})
	var unsupported *avmsim.UnsupportedError
	if errors.As(err, &unsupported) {
		// An interpreter limit is not a rejection: reading it as one would let
		// every negative case pass on a path the interpreter cannot run.
		r.t.Fatalf("the verifier reached something the interpreter cannot run: %v", err)
	}
	return ok && err == nil
}

func (r *verifierRig) teal(txid, sig []byte) bool {
	r.t.Helper()
	return r.runTxn(defaultTxn(txid), sig)
}

// check requires the verifier and the Go primitive to agree and returns the
// verdict.
func (r *verifierRig) check(name string, txid, sig []byte) bool {
	r.t.Helper()
	inTeal, inGo := r.teal(txid, sig), wotsc.Verify(&r.sk.Public, txid, sig) == nil
	if inTeal != inGo {
		r.t.Fatalf("%s: TEAL %v, Go %v", name, inTeal, inGo)
	}
	return inTeal
}

func message(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

func (r *verifierRig) sign(leaf uint32, txid []byte) []byte {
	r.t.Helper()
	sig, err := r.sk.Sign(leaf, txid)
	if err != nil {
		r.t.Fatal(err)
	}
	return sig
}

// th is the tweakable hash, written out here so these signatures don't come
// from the primitive under comparison.
func th(pkSeed []byte, kind byte, keypair, chain, index uint32, m []byte) []byte {
	in := append(slices.Clone(pkSeed), make([]byte, 48+10)...)
	in[64+9] = kind
	in = binary.BigEndian.AppendUint32(in, keypair)
	in = binary.BigEndian.AppendUint32(in, chain)
	in = binary.BigEndian.AppendUint32(in, index)
	sum := sha256.Sum256(append(in, m...))
	return sum[:wotsc.N]
}

// honestSignature builds the signature for any randomizer, whatever its digit
// sum. Every chain reaches the public key, so only the sum check rejects it.
func (r *verifierRig) honestSignature(leaf uint32, txid []byte, randomizer *[wotsc.N]byte) []byte {
	r.t.Helper()
	pkSeed := r.sk.Public.Seed[:]
	digits, _ := wotsc.Digits(&r.sk.Public, randomizer, leaf, txid)
	sig := r.sign(leaf, txid)
	copy(sig[offsetR:], randomizer[:])
	for j := range uint32(wotsc.Len) {
		x := th(pkSeed, 5, leaf, j, 0, r.sk.SKSeed[:])
		for k := range uint32(digits[j]) {
			x = th(pkSeed, 0, leaf, j, k, x)
		}
		copy(sig[offsetChains+j*wotsc.N:], x)
	}
	return sig
}

func TestVerifierAgreesWithPrimitive(t *testing.T) {
	r := newVerifierRig(t, 1)
	for i := range 64 {
		txid := message(fmt.Sprintf("message %d", i))
		leaf := uint32(i)
		if !r.check("valid", txid, r.sign(leaf, txid)) {
			t.Fatalf("leaf %d: valid signature rejected", leaf)
		}
		if got, want := r.lastEqual[0].Bytes(), r.lastEqual[1].Bytes(); len(got) != wotsc.N || !bytes.Equal(got, want) || !bytes.Equal(want, r.sk.Public.Root[:]) {
			t.Fatalf("leaf %d: the final comparison was %x against %x", leaf, got, want)
		}
	}
	if r.hooked != 2*64 {
		t.Fatalf("classical checks ran %d times, want %d", r.hooked, 2*64)
	}
}

func TestVerifierRejects(t *testing.T) {
	r := newVerifierRig(t, 2)
	txid := message("first")
	const leaf = 37
	sig := r.sign(leaf, txid)
	if !r.check("valid", txid, sig) {
		t.Fatal("valid signature rejected")
	}
	rejected := func(name string, txid, sig []byte) {
		t.Helper()
		if r.check(name, txid, sig) {
			t.Fatalf("%s accepted", name)
		}
	}
	for at := range sig {
		flipped := slices.Clone(sig)
		flipped[at] ^= 1 << (at % 8)
		rejected(fmt.Sprintf("byte %d flipped", at), txid, flipped)
	}
	rejected("other message", message("second"), sig)
	if newVerifierRig(t, 3).teal(txid, sig) {
		t.Fatal("verified under another key")
	}
	rejected("one byte short", txid, sig[:len(sig)-1])
	rejected("one byte long", txid, append(slices.Clone(sig), 0))
	rejected("empty", txid, nil)

	for _, index := range []uint32{64, 65, 100, 1 << 16, 1 << 31, ^uint32(0)} {
		high := slices.Clone(sig)
		binary.BigEndian.PutUint32(high, index)
		rejected(fmt.Sprintf("leaf %d", index), txid, high)
	}
	// Right sizes, wrong arrangement.
	swappedChains := slices.Clone(sig)
	copy(swappedChains[offsetChains:], sig[offsetChains+wotsc.N:offsetChains+2*wotsc.N])
	copy(swappedChains[offsetChains+wotsc.N:], sig[offsetChains:offsetChains+wotsc.N])
	rejected("exchanged chains", txid, swappedChains)
	swappedPath := slices.Clone(sig)
	copy(swappedPath[offsetAuth:], sig[offsetAuth+wotsc.N:offsetAuth+2*wotsc.N])
	copy(swappedPath[offsetAuth+wotsc.N:], sig[offsetAuth:offsetAuth+wotsc.N])
	rejected("exchanged path nodes", txid, swappedPath)
	otherLeaf := slices.Clone(sig)
	binary.BigEndian.PutUint32(otherLeaf, leaf+1)
	rejected("signature on another leaf's index", txid, otherLeaf)
}

func TestVerifierRejectsWrongDigitSum(t *testing.T) {
	r := newVerifierRig(t, 4)
	txid := message("sum")
	const leaf = 11
	seen := map[bool]bool{}
	for c := 0; len(seen) < 2; c++ {
		var randomizer [wotsc.N]byte
		copy(randomizer[:], message(fmt.Sprintf("r %d", c)))
		_, sum := wotsc.Digits(&r.sk.Public, &randomizer, leaf, txid)
		if sum == wotsc.TargetSum {
			continue
		}
		seen[sum > wotsc.TargetSum] = true
		if r.check("wrong digit sum", txid, r.honestSignature(leaf, txid, &randomizer)) {
			t.Fatalf("digit sum %d accepted", sum)
		}
	}
	// The hand-built signature is otherwise exact: it equals the real one
	// when given the real randomizer.
	sig := r.sign(leaf, txid)
	var randomizer [wotsc.N]byte
	copy(randomizer[:], sig[offsetR:])
	if !bytes.Equal(r.honestSignature(leaf, txid, &randomizer), sig) {
		t.Fatal("honestSignature doesn't reproduce a real signature, so the rejections above prove nothing")
	}
}

func TestVerifierGuards(t *testing.T) {
	r := newVerifierRig(t, 5)
	txid := message("guards")
	sig := r.sign(3, txid)
	if !r.teal(txid, sig) {
		t.Fatal("valid signature rejected")
	}
	for name, mutate := range map[string]func(*avmsim.Txn){
		"no rekey":        func(x *avmsim.Txn) { x.RekeyTo = make([]byte, 32) },
		"rekey to sender": func(x *avmsim.Txn) { x.RekeyTo = x.Sender },
		"close-out":       func(x *avmsim.Txn) { x.CloseRemainderTo = bytes.Repeat([]byte{3}, 32) },
		"window of 101":   func(x *avmsim.Txn) { x.LastValid = x.FirstValid + MaxValidityWindow + 1 },
	} {
		txn := defaultTxn(txid)
		mutate(&txn)
		if r.runTxn(txn, sig) {
			t.Fatalf("%s accepted", name)
		}
	}
	window := defaultTxn(txid)
	window.LastValid = window.FirstValid + MaxValidityWindow
	if !r.runTxn(window, sig) {
		t.Fatal("a window of exactly 100 was refused")
	}
	r.hookDeny = true
	if r.teal(txid, sig) {
		t.Fatal("accepted with the classical signatures refused")
	}
}

// TestVerifierMutants damages the verifier in ways a bad edit could, and
// requires this file's checks to notice. A test suite that passes on a broken
// verifier proves nothing about the real one.
func TestVerifierMutants(t *testing.T) {
	for _, m := range []struct{ name, old, new string }{
		{"digit sum not enforced", "load 20\npushint 240\n==\nassert\n", ""},
		{"signature length not enforced", "arg 0\nlen\npushint 628\n==\nassert\n", ""},
		{"digit read from the wrong nibble", "pushint 1\nload 19\npushint 1\n&\n-\npushint 4\n*\nshr", "load 19\npushint 1\n&\npushint 4\n*\nshr"},
		{"chain ignores its number", "load 19\nitob\nextract 4 4\nconcat\nstore 24", "pushbytes 0x00000000\nconcat\nstore 24"},
		{"leaf compression has no leaf address", "arg 0\nextract 0 4\nreplace2 10\nstore 9\n", "store 9\n"},
		{"tree node ignores its height", "load 11\npushint 1\n+\nitob\nextract 4 4\nreplace2 14\n", ""},
		{"path order ignored", "load 7\nload 14\nload 23\nselect\nconcat\nload 14\nload 7\nload 23\nselect\nconcat", "load 7\nconcat\nload 14\nconcat"},
		{"root compared on 8 bytes", "load 7\nload 1\n==\nreturn", "load 7\nextract 0 8\nload 1\nextract 0 8\n==\nreturn"},
	} {
		t.Run(m.name, func(t *testing.T) {
			r := newVerifierRig(t, 6)
			source := TEALSource(r.keys)
			if strings.Count(source, m.old) != 1 {
				t.Fatalf("the mutation matches %d places", strings.Count(source, m.old))
			}
			r.assemble(strings.Replace(source, m.old, m.new, 1))
			if !mutantDetected(r) {
				t.Fatal("no check noticed this mutant")
			}
		})
	}
}

// mutantDetected reports whether the verifier gets any of these wrong: valid
// signatures on every leaf, damaged and oversized signatures, honest signatures
// with the wrong digit sum, and a full-width root comparison.
func mutantDetected(r *verifierRig) bool {
	txid := message("mutant")
	for leaf := range uint32(wotsc.Leaves) {
		if !r.teal(txid, r.sign(leaf, txid)) {
			return true
		}
	}
	sig := r.sign(9, txid)
	for at := 0; at < wotsc.SignatureSize; at += 3 {
		flipped := slices.Clone(sig)
		flipped[at] ^= 1
		if r.teal(txid, flipped) {
			return true
		}
	}
	if r.teal(txid, append(slices.Clone(sig), 0)) {
		return true
	}
	for c := range 40 {
		var randomizer [wotsc.N]byte
		copy(randomizer[:], message(fmt.Sprintf("mutant r %d", c)))
		if _, sum := wotsc.Digits(&r.sk.Public, &randomizer, 9, txid); sum != wotsc.TargetSum && r.teal(txid, r.honestSignature(9, txid, &randomizer)) {
			return true
		}
	}
	// The last comparison of a valid run must cover the whole root.
	if !r.teal(txid, sig) {
		return true
	}
	return len(r.lastEqual[0].Bytes()) != wotsc.N
}
