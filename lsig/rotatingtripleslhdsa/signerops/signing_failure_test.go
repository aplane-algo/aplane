// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
	"github.com/aplane-algo/aplane/internal/signing"
)

var failureTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("signing failure test message"))
	return sum[:]
}()

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// observeSLH makes signSLH record every SLH-DSA signature it returns, after
// corrupt (when not nil) has changed it, until the test ends.
func observeSLH(t *testing.T, corrupt func([]byte)) *[][]byte {
	t.Helper()
	made := &[][]byte{}
	restore := signSLH
	t.Cleanup(func() { signSLH = restore })
	signSLH = func(key *slhdsa.SigningKey, message []byte) ([]byte, error) {
		sig, err := restore(key, message)
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
	seed, genesis := fixedSeed()
	return &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
}

// TestFalconFailureWipesTheSLHSignature makes Falcon signing fail after the
// SLH-DSA signature was made, as a zeroed Falcon key does, and checks that
// the SLH-DSA signature is wiped.
func TestFalconFailureWipesTheSLHSignature(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	keys, _, err := DeriveStage(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	made := observeSLH(t, nil)
	keys.classical.Zero()
	if h, e, f, err := keys.Sign(failureTestMessage); err == nil || h != nil || e != nil || f != nil {
		t.Fatalf("Sign returned %d, %d and %d bytes, err %v: want a failure and no signatures", len(h), len(e), len(f), err)
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the SLH-DSA signature made before the Falcon failure was not wiped")
	}
}

// TestRefusedSignatureIsWiped corrupts the SLH-DSA signature so that the
// stage's own verification refuses it, and checks that SignStage wipes it.
// SignStage splits the signature into arguments; wiping them must wipe all
// of it.
func TestRefusedSignatureIsWiped(t *testing.T) {
	made := observeSLH(t, func(sig []byte) { sig[len(sig)-1] ^= 1 })
	if _, err := (StageOps{}).SignStage(fixedKeyMaterial(), 0, 0, failureTestMessage); err == nil {
		t.Fatal("SignStage released a signature that does not verify")
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the refused SLH-DSA signature was not wiped")
	}
}

// TestSignStageRefusesOtherMessageSizes checks that a message that is not a
// 32-byte transaction ID is refused before anything is signed.
func TestSignStageRefusesOtherMessageSizes(t *testing.T) {
	made := observeSLH(t, nil)
	for _, n := range []int{0, 31, 33} {
		if _, err := (StageOps{}).SignStage(fixedKeyMaterial(), 0, 0, make([]byte, n)); err == nil {
			t.Errorf("%d-byte message was signed", n)
		}
	}
	if len(*made) != 0 {
		t.Fatal("a refused message reached the SLH-DSA key")
	}
}
