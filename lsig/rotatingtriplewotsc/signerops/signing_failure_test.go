// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/internal/signing"
)

var failureTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("signing failure test message"))
	return sum[:]
}()

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// observeHash makes signHash record every WOTS+C signature it returns, after
// corrupt (when not nil) has changed it, until the test ends.
func observeHash(t *testing.T, corrupt func([]byte)) *[][]byte {
	t.Helper()
	made := &[][]byte{}
	restore := signHash
	t.Cleanup(func() { signHash = restore })
	signHash = func(key *wotsc.SigningKey, leaf uint32, message []byte) ([]byte, error) {
		sig, err := restore(key, leaf, message)
		if err == nil {
			if corrupt != nil {
				corrupt(sig)
			}
			*made = append(*made, sig)
		}
		return sig, err
	}
	return made
}

func fixedKeyMaterial() *signing.RotatingKeyMaterial {
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for i := range genesis {
		genesis[i] = byte(0xA0 + i)
	}
	return &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
}

// A leaf is one-time, and the open test runs on a stage that hasn't spent. If
// it signed with a leaf, every rotation would spend one before the stage's
// first real signature.
func TestCheckStageOpensNeverSignsWithALeaf(t *testing.T) {
	made := observeHash(t, nil)
	if err := (StageOps{}).CheckStageOpens(fixedKeyMaterial(), 3); err != nil {
		t.Fatal(err)
	}
	if len(*made) != 0 {
		t.Fatalf("the open test signed with %d leaves", len(*made))
	}
}

func TestSignStageUsesTheGivenLeaf(t *testing.T) {
	for _, leaf := range []uint32{0, 17, 63} {
		sig, err := (StageOps{}).SignStage(fixedKeyMaterial(), 2, leaf, failureTestMessage)
		if err != nil {
			t.Fatal(err)
		}
		got := uint32(sig.Args[0][0])<<24 | uint32(sig.Args[0][1])<<16 | uint32(sig.Args[0][2])<<8 | uint32(sig.Args[0][3])
		if got != leaf {
			t.Fatalf("signed with leaf %d, asked for %d", got, leaf)
		}
	}
	if _, err := (StageOps{}).SignStage(fixedKeyMaterial(), 2, wotsc.Leaves, failureTestMessage); err == nil {
		t.Fatal("signed with a leaf outside the tree")
	}
}

// TestFalconFailureWipesTheHashSignature makes Falcon signing fail after the
// WOTS+C signature was made, as a zeroed Falcon key does, and checks that the
// WOTS+C signature is wiped.
func TestFalconFailureWipesTheHashSignature(t *testing.T) {
	keys, _ := deriveStage(t, testDeriver(t, 1, 2), 0)
	made := observeHash(t, nil)
	keys.classical.Zero()
	if h, e, f, err := keys.Sign(0, failureTestMessage); err == nil || h != nil || e != nil || f != nil {
		t.Fatalf("Sign returned %d, %d and %d bytes, err %v: want a failure and no signatures", len(h), len(e), len(f), err)
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the WOTS+C signature made before the Falcon failure was not wiped")
	}
}

// TestRefusedSignatureIsWiped corrupts the WOTS+C signature so that the stage's
// own verification refuses it, and checks that SignStage wipes it.
func TestRefusedSignatureIsWiped(t *testing.T) {
	made := observeHash(t, func(sig []byte) { sig[len(sig)-1] ^= 1 })
	if _, err := (StageOps{}).SignStage(fixedKeyMaterial(), 0, 0, failureTestMessage); err == nil {
		t.Fatal("SignStage released a signature that does not verify")
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the refused WOTS+C signature was not wiped")
	}
}

// TestSignStageRefusesOtherMessageSizes checks that a message that is not a
// 32-byte transaction ID is refused before anything is signed.
func TestSignStageRefusesOtherMessageSizes(t *testing.T) {
	made := observeHash(t, nil)
	for _, n := range []int{0, 31, 33} {
		if _, err := (StageOps{}).SignStage(fixedKeyMaterial(), 0, 0, make([]byte, n)); err == nil {
			t.Errorf("%d-byte message was signed", n)
		}
	}
	if len(*made) != 0 {
		t.Fatal("a refused message reached the WOTS+C key")
	}
}
