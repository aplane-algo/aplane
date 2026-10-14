// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package wots

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func fixedKey(t *testing.T) (*Tweak, []byte, PublicKey) {
	t.Helper()
	tw := NewTweak([N]byte{1}, [N]byte{2}, 7)
	sk := make([]byte, SecretKeySize)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	pk, err := PublicKeyOf(&tw, sk)
	if err != nil {
		t.Fatal(err)
	}
	return &tw, sk, pk
}

func TestSignVerifyRoundTrip(t *testing.T) {
	tw, sk, pk := fixedKey(t)
	for range 8 {
		msg := make([]byte, MessageSize)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(tw, sk, msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != SignatureSize {
			t.Fatalf("signature is %d bytes", len(sig))
		}
		if err := Verify(tw, pk, msg, sig); err != nil {
			t.Fatalf("honest signature rejected: %v", err)
		}
		again, _ := Sign(tw, sk, msg)
		if !bytes.Equal(sig, again) {
			t.Fatal("signing is not deterministic")
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	tw, sk, pk := fixedKey(t)
	msg := bytes.Repeat([]byte{0x5a}, MessageSize)
	sig, err := Sign(tw, sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{0x5b}, MessageSize)
	if Verify(tw, pk, other, sig) == nil {
		t.Fatal("signature accepted for another message")
	}
	flipped := bytes.Clone(sig)
	flipped[100] ^= 1
	if Verify(tw, pk, msg, flipped) == nil {
		t.Fatal("tampered signature accepted")
	}
	otherTweak := NewTweak([N]byte{1}, [N]byte{2}, 8)
	if Verify(&otherTweak, pk, msg, sig) == nil {
		t.Fatal("signature accepted under another stage's tweak")
	}
	if Verify(tw, pk, msg, sig[:SignatureSize-1]) == nil {
		t.Fatal("short signature accepted")
	}
	if _, err := Sign(tw, sk, msg[:31]); err == nil {
		t.Fatal("31-byte message signed")
	}
}

func TestDigitsAndChecksum(t *testing.T) {
	msg := make([]byte, MessageSize)
	msg[0] = 0xA7
	d, err := Digits(msg)
	if err != nil {
		t.Fatal(err)
	}
	if d[0] != 0xA || d[1] != 0x7 || d[2] != 0 {
		t.Fatalf("digits = %v", d[:3])
	}
	// sum(15 - digit) = (15-10) + (15-7) + 62*15 = 943 = 0x3AF
	if d[Len1] != 3 || d[Len1+1] != 0xA || d[Len1+2] != 0xF {
		t.Fatalf("checksum digits = %v", d[Len1:])
	}
	steps, _ := VerifySteps(msg)
	// message steps = 943 - wait: verify steps = sum(15 - digit) over all 67
	want := 943 + (15 - 3) + (15 - 0xA) + (15 - 0xF)
	if steps != want {
		t.Fatalf("VerifySteps = %d, want %d", steps, want)
	}
	zero, _ := VerifySteps(make([]byte, MessageSize))
	if zero != MaxVerifySteps {
		t.Fatalf("all-zero message needs %d steps, MaxVerifySteps = %d", zero, MaxVerifySteps)
	}
	for range 256 {
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		s, _ := VerifySteps(msg)
		if s > MaxVerifySteps {
			t.Fatalf("message needs %d steps, above the maximum %d", s, MaxVerifySteps)
		}
	}
}

// TestChainHashMatchesAVMShape pins F to the byte layout the stage program
// reproduces with pushbytes T; itob(c*256+j); concat; x; concat; sha256.
func TestChainHashMatchesAVMShape(t *testing.T) {
	tw := NewTweak([N]byte{9}, [N]byte{8}, 3)
	x := bytes.Repeat([]byte{0xee}, N)
	got := F(&tw, 66, 14, x)
	var enc [8]byte
	binary.BigEndian.PutUint64(enc[:], 66*256+14)
	want := sha256.Sum256(append(append(append([]byte{}, tw[:]...), enc[:]...), x...))
	if got != want {
		t.Fatal("F does not match the AVM concatenation order")
	}
}
