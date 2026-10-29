// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/internal/signing"
)

var failureTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("signing failure test message"))
	return sum[:]
}()

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// observeWots makes signWots record every WOTS signature it returns, after
// corrupt (when not nil) has changed it, until the test ends.
func observeWots(t *testing.T, corrupt func([]byte)) *[][]byte {
	t.Helper()
	made := &[][]byte{}
	restore := signWots
	t.Cleanup(func() { signWots = restore })
	signWots = func(tweak *wots.Tweak, sk, message []byte) ([]byte, error) {
		sig, err := restore(tweak, sk, message)
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

// TestFalconFailureWipesTheWotsSignature makes Falcon signing fail after the
// WOTS signature was made, as a zeroed Falcon key does, and checks that the
// WOTS signature, which carries chain secrets, is wiped.
func TestFalconFailureWipesTheWotsSignature(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	keys, _, err := DeriveStage(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	made := observeWots(t, nil)
	keys.classical.Zero()
	if w, e, f, err := keys.Sign(failureTestMessage); err == nil || w != nil || e != nil || f != nil {
		t.Fatalf("Sign returned %d, %d and %d bytes, err %v: want a failure and no signatures", len(w), len(e), len(f), err)
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the WOTS signature made before the Falcon failure was not wiped")
	}
}

// TestRefusedSignatureIsWiped corrupts the WOTS signature so that the stage's
// own verification refuses it, and checks that SignStage wipes it.
func TestRefusedSignatureIsWiped(t *testing.T) {
	seed, genesis := fixedSeed()
	key := &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
	made := observeWots(t, func(sig []byte) { sig[len(sig)-1] ^= 1 })
	if _, err := (StageOps{}).SignStage(key, 0, 0, failureTestMessage); err == nil {
		t.Fatal("SignStage released a signature that does not verify")
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the refused WOTS signature was not wiped")
	}
}

// TestSignStageRefusesOtherMessageSizes checks that a message that is not a
// 32-byte transaction ID is refused before anything is signed.
func TestSignStageRefusesOtherMessageSizes(t *testing.T) {
	seed, genesis := fixedSeed()
	key := &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
	made := observeWots(t, nil)
	for _, n := range []int{0, 31, 33} {
		if _, err := (StageOps{}).SignStage(key, 0, 0, make([]byte, n)); err == nil {
			t.Errorf("%d-byte message was signed", n)
		}
	}
	if len(*made) != 0 {
		t.Fatal("a refused message reached the WOTS key")
	}
}
