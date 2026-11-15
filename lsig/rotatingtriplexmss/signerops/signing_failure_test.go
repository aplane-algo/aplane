// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stagesign"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

var failureTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("signing failure test message"))
	return sum[:]
}()

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// observeXmss makes signXmss record every XMSS signature it returns, after
// corrupt (when not nil) has changed it, until the test ends.
func observeXmss(t *testing.T, corrupt func([]byte)) *[][]byte {
	t.Helper()
	made := &[][]byte{}
	restore := signXmss
	t.Cleanup(func() { signXmss = restore })
	signXmss = func(seeds *xmss.Seeds, tree *xmss.Tree, index uint32, message []byte, maxChecksum int) ([]byte, error) {
		sig, err := restore(seeds, tree, index, message, maxChecksum)
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

// fixedStageOps returns stage ops whose cache already holds the fixed seed's
// trees, and the fixed seed's key material.
func fixedStageOps(t *testing.T) (*StageOps, *signing.RotatingKeyMaterial) {
	t.Helper()
	seed, genesis := fixedSeed()
	d := fixedDeriver(t)
	defer d.Zero()
	tag, err := AccountTag(d)
	if err != nil {
		t.Fatal(err)
	}
	ops := NewStageOps()
	ops.insert(treeKey{tag: tag, genesis: genesis, tree: 0}, fixedTree(t, 0))
	return ops, &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
}

// TestFalconFailureWipesTheXmssSignature makes Falcon signing fail after the
// XMSS signature was made, as a zeroed Falcon key does, and checks that the
// XMSS signature is wiped.
func TestFalconFailureWipesTheXmssSignature(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	keys, _, err := DeriveStage(d, 0, fixedTree(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	made := observeXmss(t, nil)
	keys.classical.Zero()
	if x, e, f, err := keys.Sign(failureTestMessage, 3); err == nil || x != nil || e != nil || f != nil {
		t.Fatalf("Sign returned %d, %d and %d bytes, err %v: want a failure and no signatures", len(x), len(e), len(f), err)
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the XMSS signature made before the Falcon failure was not wiped")
	}
}

// TestRefusedSignatureIsWiped corrupts the XMSS signature so that the stage's
// own verification refuses it, and checks that SignStage wipes it.
func TestRefusedSignatureIsWiped(t *testing.T) {
	ops, key := fixedStageOps(t)
	made := observeXmss(t, func(sig []byte) { sig[len(sig)-1] ^= 1 })
	if _, err := ops.SignStage(key, 0, 3, failureTestMessage); err == nil {
		t.Fatal("SignStage released a signature that does not verify")
	}
	if len(*made) != 1 || !allZero((*made)[0]) {
		t.Fatal("the refused XMSS signature was not wiped")
	}
}

// TestSignStageRefusesOtherMessageSizes checks that a message that is not a
// 32-byte transaction ID is refused before anything is signed.
func TestSignStageRefusesOtherMessageSizes(t *testing.T) {
	ops, key := fixedStageOps(t)
	made := observeXmss(t, nil)
	for _, n := range []int{0, 31, 33} {
		if _, err := ops.SignStage(key, 0, 3, make([]byte, n)); err == nil {
			t.Errorf("%d-byte message was signed", n)
		}
	}
	if len(*made) != 0 {
		t.Fatal("a refused message reached an XMSS leaf")
	}
}

// deriveAnotherStage makes derivation build programs that embed a stage
// number a tree further on than the stage derived, until the test ends. The
// leaf range, and every key, are the stage's own, so only the stage number
// is wrong and the signatures would verify.
func deriveAnotherStage(t *testing.T) {
	t.Helper()
	restore := buildProgram
	t.Cleanup(func() { buildProgram = restore })
	buildProgram = func(keys *stage.PublicKeys) (stage.Program, error) {
		other := *keys
		other.Stage += stage.StagesPerTree
		return restore(&other)
	}
}

// TestSignStageRefusesAProgramOfAnotherStage checks that SignStage refuses a
// derived program that embeds another stage number before any key signs: no
// XMSS leaf is used for a refusal that depends only on the program.
func TestSignStageRefusesAProgramOfAnotherStage(t *testing.T) {
	ops, key := fixedStageOps(t)
	made := observeXmss(t, nil)
	deriveAnotherStage(t)
	sig, err := ops.SignStage(key, 0, 3, failureTestMessage)
	if !errors.Is(err, stagesign.ErrStageMismatch) || !strings.Contains(err.Error(), "stage 0 program embeds stage 1024") {
		t.Fatalf("SignStage for stage 0 with a stage 1024 program: %v", err)
	}
	if sig.Program != nil || sig.Args != nil {
		t.Fatal("SignStage returned a program or signatures with its refusal")
	}
	if len(*made) != 0 {
		t.Fatalf("SignStage signed with %d XMSS leaves before refusing the program", len(*made))
	}
}

// TestCheckStageOpensRefusesAProgramOfAnotherStage checks that the open test
// of a rotation target refuses a program that embeds another stage number,
// before the account could be rekeyed to it.
func TestCheckStageOpensRefusesAProgramOfAnotherStage(t *testing.T) {
	ops, key := fixedStageOps(t)
	deriveAnotherStage(t)
	if err := ops.CheckStageOpens(key, 1); !errors.Is(err, stagesign.ErrStageMismatch) || !strings.Contains(err.Error(), "stage 1 program embeds stage 1025") {
		t.Fatalf("CheckStageOpens for stage 1 with a stage 1025 program: %v", err)
	}
}
