// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/avmsim"
	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
)

// verifierRig runs a hypertree shape's TEAL verifier in the interpreter
// against the Go primitive for the same key.
type verifierRig struct {
	t      *testing.T
	shape  hypertree
	sk     *slhdsa.SigningKey
	prog   *avmsim.Program
	hooked int
	// lastEqual is the operand pair of the most recent == the program ran.
	lastEqual [2]avmsim.Value
}

func newVerifierRig(t *testing.T, shape hypertree, tag byte) *verifierRig {
	t.Helper()
	var skSeed, skPrf, pkSeed [slhdsa.N]byte
	for i := range skSeed {
		skSeed[i], skPrf[i], pkSeed[i] = tag+byte(i), tag^byte(3*i), tag+byte(5*i)
	}
	sk := shape.params.KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	keys := &PublicKeys{Seed: sk.Public.Seed, Root: sk.Public.Root}
	for i := range keys.Ed25519 {
		keys.Ed25519[i] = tag ^ byte(i)
	}
	for i := range keys.Falcon {
		keys.Falcon[i] = tag + byte(i%251)
	}
	prog, err := avmsim.Assemble(substitute(shape.teal, keys))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return &verifierRig{t: t, shape: shape, sk: sk, prog: prog}
}

// split cuts an SLH-DSA signature into the verifier's arguments.
func (r *verifierRig) split(sig []byte) [][]byte {
	if len(sig) != r.shape.params.SignatureSize {
		r.t.Fatalf("signature is %d bytes, want %d", len(sig), r.shape.params.SignatureSize)
	}
	var args [][]byte
	for _, n := range r.shape.chunks {
		args = append(args, sig[:n])
		sig = sig[n:]
	}
	return args
}

// teal runs the verifier on a presented signature. The Ed25519 and Falcon
// opcodes are stubbed to accept: the property under test is the SLH-DSA leg.
func (r *verifierRig) teal(txid, sig []byte) bool {
	r.t.Helper()
	return r.tealArgs(txid, r.split(sig))
}

// tealArgs runs the verifier on explicit SLH-DSA arguments, which need not
// have the right sizes.
func (r *verifierRig) tealArgs(txid []byte, slhArgs [][]byte) bool {
	r.t.Helper()
	args := append(slices.Clone(slhArgs), []byte("ed25519 signature"), []byte("falcon signature"))
	ok, err := r.prog.Run(avmsim.Txn{
		"TxID":       avmsim.B(txid),
		"Sender":     avmsim.B(bytes.Repeat([]byte{1}, 32)),
		"RekeyTo":    avmsim.B(bytes.Repeat([]byte{2}, 32)),
		"FirstValid": avmsim.U(1000), "LastValid": avmsim.U(1100),
		"CloseRemainderTo": avmsim.B(make([]byte, 32)),
	}, args, avmsim.Hooks{
		Ed25519: func(_, _, _ []byte) bool { r.hooked++; return true },
		Falcon:  func(_, _, _ []byte) bool { r.hooked++; return true },
		Equal:   func(a, b avmsim.Value) { r.lastEqual = [2]avmsim.Value{a, b} },
	})
	var unsupported *avmsim.UnsupportedError
	if errors.As(err, &unsupported) {
		// An interpreter limit is not a rejection: reading it as one would let
		// every negative case pass on a path the interpreter cannot run.
		r.t.Fatalf("the verifier reached something the interpreter cannot run: %v", err)
	}
	if err != nil && !isRejection(err) {
		// A modeled AVM fault is a rejection on chain; keep the reason.
		r.t.Logf("verifier faulted: %v", err)
	}
	return ok
}

func isRejection(err error) bool { return err == avmsim.ErrReject }

func (r *verifierRig) goVerify(txid, sig []byte) bool {
	return r.shape.params.Verify(&r.sk.Public, txid, sig, nil) == nil
}

// check asserts the two verifiers agree and returns the shared verdict.
func (r *verifierRig) check(name string, txid, sig []byte) bool {
	r.t.Helper()
	want, got := r.goVerify(txid, sig), r.teal(txid, sig)
	if want != got {
		r.t.Fatalf("%s: slhdsa.Verify = %v, TEAL verifier = %v", name, want, got)
	}
	return got
}

func testTxID(n int) []byte {
	h := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("verifier equivalence"), uint64(n)))
	return h[:]
}

// TestVerifierMatchesPrimitive runs each shape's real TEAL verifier source in
// the interpreter and requires it to accept exactly what slhdsa.Verify
// accepts: valid signatures (eight messages on the rescaled shape, one on the
// full-height shape, for distinct FORS indices, hypertree paths and WOTS+
// digits), and for the first message a signature with one bit flipped at the
// start of every 16-byte node, which both must reject.
func TestVerifierMatchesPrimitive(t *testing.T) {
	for height, shape := range hypertrees {
		t.Run(shape.params.Name, func(t *testing.T) {
			if height != 22 && testing.Short() {
				t.Skip("the full-height set signs slowly")
			}
			// The full-height set signs slowly, so it gets one message; both
			// shapes get a flipped bit at every 16-byte node boundary.
			const stride = 16
			messages := 8
			if height != 22 {
				messages = 1
			}
			r := newVerifierRig(t, shape, byte(height))
			var first []byte
			var firstID []byte
			for i := 0; i < messages; i++ {
				txid := testTxID(i)
				sig, err := shape.params.Sign(r.sk, txid, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !r.check("valid signature", txid, sig) {
					t.Fatalf("message %d: a valid signature was rejected", i)
				}
				if i == 0 {
					first, firstID = sig, txid
				}
			}
			// The program ends by comparing the rebuilt hypertree root with the
			// key's root. Random tampering cannot tell a full-width comparison
			// from a truncated one (a wrong root still differs in byte 0), so
			// pin the operands of the last comparison directly.
			r.teal(firstID, first)
			if got, want := r.lastEqual[0].Bytes(), r.lastEqual[1].Bytes(); len(got) != slhdsa.N || !bytes.Equal(got, want) || !bytes.Equal(want, r.sk.Public.Root[:]) {
				t.Fatalf("final comparison operands = %x, %x; want the full %d-byte root %x", got, want, slhdsa.N, r.sk.Public.Root)
			}
			if r.hooked == 0 {
				t.Fatal("the verifier never reached the Ed25519 and Falcon checks")
			}

			// One flipped bit at the start of every stride-byte block.
			rejected := 0
			for off := 0; off < len(first); off += stride {
				bad := bytes.Clone(first)
				bad[off] ^= 1 << (uint(off/stride) % 8)
				if r.check("tampered signature", firstID, bad) {
					t.Fatalf("a signature with byte %d flipped was accepted", off)
				}
				rejected++
			}
			t.Logf("%d tampered signatures rejected by both", rejected)

			// The edges: the last byte, the message, the key, the lengths.
			bad := bytes.Clone(first)
			bad[len(bad)-1] ^= 0x80
			if r.check("last byte", firstID, bad) {
				t.Fatal("last-byte tamper accepted")
			}
			if r.check("other message", testTxID(1000), first) {
				t.Fatal("signature accepted for another message")
			}
			other := newVerifierRig(t, shape, byte(height)+1)
			if other.goVerify(firstID, first) || other.teal(firstID, first) {
				t.Fatal("signature accepted under another key")
			}
			good := r.split(first)
			short := slices.Clone(good)
			short[len(short)-1] = short[len(short)-1][:len(short[len(short)-1])-1]
			long := slices.Clone(good)
			long[0] = append(bytes.Clone(long[0]), 0)
			if r.tealArgs(firstID, short) || r.tealArgs(firstID, long) || r.tealArgs(firstID, good[:1]) {
				t.Fatal("wrong-length signature accepted")
			}
			// Two hypertree layers exchanged: sizes are right, content is not.
			swapped := bytes.Clone(first)
			layer := slhdsa.WotsSignatureSize + int(shape.params.HPrime)*slhdsa.N
			base := shape.chunks[0]
			copy(swapped[base:base+layer], first[base+layer:base+2*layer])
			copy(swapped[base+layer:base+2*layer], first[base:base+layer])
			if r.check("swapped layers", firstID, swapped) {
				t.Fatal("swapped hypertree layers accepted")
			}
		})
	}
}
