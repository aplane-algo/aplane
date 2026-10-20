// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package wots implements the Winternitz one-time signature used by the
// aplane.rotating-triple-wots.v1 stage program: n = 32, w = 16, 64 message
// digits plus 3 checksum digits over a 32-byte message, 67 hash chains of 15
// steps, SHA-256 only. The chain hash is the SPHINCS+ "simple" tweakable
// hash: F(T, c, j, x) = SHA-256(T || u64be(c*256 + j) || x), so an AVM
// program verifies it with pushbytes, itob, concat and sha256.
//
// A key signs one message. Signing two different messages with one key
// reveals chain values that let a third be forged; the rotating flow is what
// keeps that from mattering, and the stage program pairs every signature with
// an Ed25519 one.
package wots

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// N is the hash and chain element size.
	N = 32

	// W is the Winternitz parameter: 4-bit digits, 15 chain steps.
	W = 16

	// Steps is the number of hash steps from a secret to a chain end.
	Steps = W - 1

	// Len1 and Len2 are the message and checksum digit counts.
	Len1 = 64
	Len2 = 3

	// Len is the number of chains.
	Len = Len1 + Len2

	// MessageSize is the only message length: a transaction ID.
	MessageSize = 32

	// SecretKeySize and SignatureSize are Len chain elements each.
	SecretKeySize = Len * N
	SignatureSize = Len * N

	// Domain separates the stage tweak from every other SHA-256 use.
	Domain = "APLANE_WOTS_V1"
)

// Tweak is the per-stage public value mixed into every chain hash.
type Tweak [N]byte

// PublicKey is the hash of the 67 chain ends.
type PublicKey [N]byte

// NewTweak derives a stage tweak:
// SHA-256(Domain || genesisHash || accountTag || u64be(stage)).
func NewTweak(genesisHash, accountTag [N]byte, stage uint64) Tweak {
	h := sha256.New()
	h.Write([]byte(Domain))
	h.Write(genesisHash[:])
	h.Write(accountTag[:])
	var enc [8]byte
	binary.BigEndian.PutUint64(enc[:], stage)
	h.Write(enc[:])
	var t Tweak
	copy(t[:], h.Sum(nil))
	return t
}

// Digits returns the 64 base-16 message digits (high nibble first) and the
// 3 checksum digits of a 32-byte message. The checksum
// sum(15 - digit) is at most 960, so three nibbles hold it.
func Digits(msg []byte) ([Len]uint8, error) {
	var d [Len]uint8
	if len(msg) != MessageSize {
		return d, fmt.Errorf("wots message is %d bytes, want %d", len(msg), MessageSize)
	}
	sum := 0
	for i, b := range msg {
		d[2*i] = b >> 4
		d[2*i+1] = b & 15
		sum += (Steps - int(d[2*i])) + (Steps - int(d[2*i+1]))
	}
	d[Len1] = uint8((sum >> 8) & 15)
	d[Len1+1] = uint8((sum >> 4) & 15)
	d[Len1+2] = uint8(sum & 15)
	return d, nil
}

// F is one chain step: SHA-256(T || u64be(chain*256 + step) || x).
func F(t *Tweak, chain, step int, x []byte) [N]byte {
	h := sha256.New()
	h.Write(t[:])
	var enc [8]byte
	binary.BigEndian.PutUint64(enc[:], uint64(chain)*256+uint64(step))
	h.Write(enc[:])
	h.Write(x)
	var out [N]byte
	copy(out[:], h.Sum(nil))
	return out
}

// advance applies steps from..to-1 of chain c to x.
func advance(t *Tweak, c int, x []byte, from, to int) [N]byte {
	var cur [N]byte
	copy(cur[:], x)
	for j := from; j < to; j++ {
		cur = F(t, c, j, cur[:])
	}
	return cur
}

// PublicKeyOf hashes the chain ends of sk, which is Len chain secrets.
func PublicKeyOf(t *Tweak, sk []byte) (PublicKey, error) {
	if len(sk) != SecretKeySize {
		return PublicKey{}, fmt.Errorf("wots secret key is %d bytes, want %d", len(sk), SecretKeySize)
	}
	h := sha256.New()
	for c := range Len {
		end := advance(t, c, sk[c*N:(c+1)*N], 0, Steps)
		h.Write(end[:])
	}
	var pk PublicKey
	copy(pk[:], h.Sum(nil))
	return pk, nil
}

// Sign returns the Len chain elements that authenticate msg under sk.
func Sign(t *Tweak, sk []byte, msg []byte) ([]byte, error) {
	if len(sk) != SecretKeySize {
		return nil, fmt.Errorf("wots secret key is %d bytes, want %d", len(sk), SecretKeySize)
	}
	d, err := Digits(msg)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SignatureSize)
	for c := range Len {
		el := advance(t, c, sk[c*N:(c+1)*N], 0, int(d[c]))
		copy(sig[c*N:], el[:])
	}
	return sig, nil
}

// Verify completes the chains from sig and compares their hash to pk.
func Verify(t *Tweak, pk PublicKey, msg, sig []byte) error {
	if len(sig) != SignatureSize {
		return fmt.Errorf("wots signature is %d bytes, want %d", len(sig), SignatureSize)
	}
	d, err := Digits(msg)
	if err != nil {
		return err
	}
	h := sha256.New()
	for c := range Len {
		end := advance(t, c, sig[c*N:(c+1)*N], int(d[c]), Steps)
		h.Write(end[:])
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), pk[:]) != 1 {
		return errors.New("wots signature is invalid")
	}
	return nil
}

// VerifySteps is the number of chain steps Verify performs for msg, which
// fixes the stage program's opcode cost for that message.
func VerifySteps(msg []byte) (int, error) {
	d, err := Digits(msg)
	if err != nil {
		return 0, err
	}
	steps := 0
	for _, v := range d {
		steps += Steps - int(v)
	}
	return steps, nil
}

// MaxVerifySteps is the most steps any message needs. All-zero message
// digits would need 64 * 15, but then the checksum is 960 = 0x3C0, whose
// digits 3, 12 and 0 need 12 + 3 + 15 more.
const MaxVerifySteps = Len1*Steps + (Steps - 3) + (Steps - 12) + Steps
