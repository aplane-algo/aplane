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

	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
)

// verifierRig runs a hypertree shape's TEAL verifier in the interpreter
// against the Go primitive for the same key.
type verifierRig struct {
	t      *testing.T
	shape  hypertree
	sk     *slhdsa.SigningKey
	prog   *avmProgram
	hooked int
	// lastEqual is the operand pair of the most recent == the program ran.
	lastEqual [2]avmValue
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
	prog, err := avmAssemble(substitute(shape.teal, keys))
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
	ok, err := r.prog.run(avmTxn{
		TxID:       txid,
		Sender:     bytes.Repeat([]byte{1}, 32),
		RekeyTo:    bytes.Repeat([]byte{2}, 32),
		FirstValid: 1000, LastValid: 1100,
		CloseRemainderTo: make([]byte, 32),
	}, args, avmHooks{
		Ed25519: func(_, _, _ []byte) bool { r.hooked++; return true },
		Falcon:  func(_, _, _ []byte) bool { r.hooked++; return true },
		Equal:   func(a, b avmValue) { r.lastEqual = [2]avmValue{a, b} },
	})
	var unsupported *avmUnsupportedError
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

func isRejection(err error) bool { return err == errAVMReject }

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
			if got, want := r.lastEqual[0].bytes, r.lastEqual[1].bytes; len(got) != slhdsa.N || !bytes.Equal(got, want) || !bytes.Equal(want, r.sk.Public.Root[:]) {
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

// TestAVMSimOpcodes pins the interpreter's reading of the opcodes whose
// semantics are easy to get backwards, so a verifier result is evidence about
// the verifier and not about the interpreter.
func TestAVMSimOpcodes(t *testing.T) {
	run := func(src string) (bool, error) {
		p, err := avmAssemble(src)
		if err != nil {
			t.Fatal(err)
		}
		return p.run(avmTxn{}, nil, avmHooks{})
	}
	pass := []struct{ name, src string }{
		{"extract zero length reads to the end", "pushbytes 0x010203\nextract 1 0\npushbytes 0x0203\n==\nreturn"},
		{"extract3", "pushbytes 0x01020304\npushint 1\npushint 2\nextract3\npushbytes 0x0203\n==\nreturn"},
		{"replace2 overwrites in place", "pushbytes 0x01020304\npushbytes 0xaabb\nreplace2 1\npushbytes 0x01aabb04\n==\nreturn"},
		{"select picks the second when true", "pushint 7\npushint 9\npushint 1\nselect\npushint 9\n==\nreturn"},
		{"select picks the first when false", "pushint 7\npushint 9\npushint 0\nselect\npushint 7\n==\nreturn"},
		{"shl wraps", "pushint 0x8000000000000001\npushint 1\nshl\npushint 2\n==\nreturn"},
		{"switch falls through out of range", "pushint 5\nswitch a b\npushint 1\nreturn\na:\npushint 0\nreturn\nb:\npushint 0\nreturn"},
		{"switch jumps", "pushint 1\nswitch a b\npushint 0\nreturn\na:\npushint 0\nreturn\nb:\npushint 1\nreturn"},
		{"getbyte and setbyte", "pushbytes 0x0102\npushint 1\npushint 9\nsetbyte\npushint 1\ngetbyte\npushint 9\n==\nreturn"},
		{"subroutine", "callsub f\nreturn\nf:\npushint 1\nretsub"},
		{"btoi", "pushbytes 0x0102\nbtoi\npushint 258\n==\nreturn"},
	}
	for _, tc := range pass {
		if ok, err := run(tc.src); !ok || err != nil {
			t.Errorf("%s: ok %v, err %v", tc.name, ok, err)
		}
	}
	faults := []struct{ name, src string }{
		{"add overflow", "pushint 18446744073709551615\npushint 1\n+\nreturn"},
		{"sub underflow", "pushint 1\npushint 2\n-\nreturn"},
		{"shift by 64", "pushint 1\npushint 64\nshr\nreturn"},
		{"concat past 4096", "pushint 4096\nbzero\npushbytes 0x00\nconcat\nreturn"},
		{"extract out of range", "pushbytes 0x01\nextract 0 2\nreturn"},
		{"replace2 out of range", "pushbytes 0x01\npushbytes 0x0203\nreplace2 0\nreturn"},
		{"type confusion", "pushbytes 0x01\npushint 1\n==\nreturn"},
		{"unknown opcode", "bitlen\nreturn"},
	}
	for _, tc := range faults {
		if ok, err := run(tc.src); ok || err == nil {
			t.Errorf("%s: ok %v, err %v, want a fault", tc.name, ok, err)
		}
	}
	// An opcode the interpreter does not know is not an AVM fault: it must
	// surface as unsupported so a harness can refuse to read it as a rejection.
	_, err := run("bitlen\nreturn")
	var unsupported *avmUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Errorf("unknown opcode error = %v, want an unsupported-by-the-interpreter error", err)
	}
	// Literal formats the interpreter does not understand are likewise
	// unsupported, not faults: base64 and string byte literals, named and
	// malformed integer constants, and instructions missing an immediate.
	for _, src := range []string{
		"pushint 1\nb nowhere",
		"global Round\nreturn",
		"pushbytes base64(AQ==)\nbtoi\nreturn",
		`pushbytes "a"` + "\nbtoi\nreturn",
		"pushbytes 0xZZ\nreturn",
		"pushbytes 0x0\nreturn",
		"pushint NoOp\nreturn",
		"pushint 18446744073709551616\nreturn",
		"pushint\nreturn",
		"pushbytes\nreturn",
		"callsub\nreturn",
	} {
		if _, err := run(src); !errors.As(err, &unsupported) {
			t.Errorf("%q: error = %v, want unsupported", src, err)
		}
	}
}
