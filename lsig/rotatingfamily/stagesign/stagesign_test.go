// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stagesign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/falconparams"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

const (
	testEd25519Tag byte = 0x02
	testFalconTag  byte = 0x01
)

func testDeriver(t *testing.T) *rotatinghybrid.Deriver {
	t.Helper()
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for i := range genesis {
		genesis[i] = byte(0xA0 + i)
	}
	d, err := rotatinghybrid.NewDeriverWithLabel(&seed, genesis, "APLANE_STAGESIGN_TEST")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Zero)
	return d
}

func testMessage() []byte {
	sum := sha256.Sum256([]byte("stagesign test message"))
	return sum[:]
}

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

func TestDeriveClassicalKeysFollowsTheDeriver(t *testing.T) {
	d := testDeriver(t)
	k, err := DeriveClassicalKeys(d, 7, testEd25519Tag, testFalconTag)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zero()
	var edSeed [rotatinghybrid.Ed25519SeedSize]byte
	if err := d.ExpandStage(testEd25519Tag, 7, edSeed[:]); err != nil {
		t.Fatal(err)
	}
	var falconSeed [rotatinghybrid.FalconSeedSize]byte
	if err := d.ExpandStage(testFalconTag, 7, falconSeed[:]); err != nil {
		t.Fatal(err)
	}
	kp, err := falcongo.GenerateKeyPair(falconSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	edKey, falconKey := k.PublicKeys()
	if !bytes.Equal(edKey[:], ed25519.NewKeyFromSeed(edSeed[:]).Public().(ed25519.PublicKey)) {
		t.Fatal("Ed25519 key is not the one the deriver's seed gives")
	}
	if falconKey != [falconparams.PublicKeySize]byte(kp.PublicKey) {
		t.Fatal("Falcon-1024 key is not the one the deriver's seed gives")
	}
	other, err := DeriveClassicalKeys(d, 8, testEd25519Tag, testFalconTag)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Zero()
	if otherEd, _ := other.PublicKeys(); otherEd == edKey {
		t.Fatal("stages 7 and 8 share an Ed25519 key")
	}
}

// TestDeriveClassicalKeysZeroesOnFailure fails each step that can fail and
// checks that what was derived before it does not survive.
func TestDeriveClassicalKeysZeroesOnFailure(t *testing.T) {
	restoreEd, restoreFalcon := newEd25519Key, generateFalconKeyPair
	t.Cleanup(func() { newEd25519Key, generateFalconKeyPair = restoreEd, restoreFalcon })

	t.Run("Falcon key generation", func(t *testing.T) {
		var edKey ed25519.PrivateKey
		var falconSeed []byte
		newEd25519Key = func(seed []byte) ed25519.PrivateKey {
			edKey = restoreEd(seed)
			return edKey
		}
		generateFalconKeyPair = func(seed []byte) (falcongo.KeyPair, error) {
			falconSeed = seed
			return falcongo.KeyPair{}, errors.New("injected failure")
		}
		k, err := DeriveClassicalKeys(testDeriver(t), 0, testEd25519Tag, testFalconTag)
		if err == nil || k != nil {
			t.Fatalf("keys %v, err %v: want a failure", k, err)
		}
		if !allZero(edKey) {
			t.Fatal("the Ed25519 key derived before the failure was not zeroed")
		}
		if !allZero(falconSeed) {
			t.Fatal("the Falcon seed was not zeroed")
		}
	})

	t.Run("seed expansion", func(t *testing.T) {
		newEd25519Key, generateFalconKeyPair = restoreEd, restoreFalcon
		d := testDeriver(t)
		d.Zero()
		if k, err := DeriveClassicalKeys(d, 0, testEd25519Tag, testFalconTag); err == nil || k != nil {
			t.Fatalf("keys %v, err %v: a zeroed deriver must fail", k, err)
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	k, err := DeriveClassicalKeys(testDeriver(t), 0, testEd25519Tag, testFalconTag)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zero()
	msg := testMessage()
	edSig, falconSig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	edKey, falconKey := k.PublicKeys()
	if err := VerifyClassical(&edKey, &falconKey, msg, edSig, falconSig); err != nil {
		t.Fatal(err)
	}

	other := testMessage()
	other[0] ^= 1
	badEd := bytes.Clone(edSig)
	badEd[0] ^= 1
	badFalcon := bytes.Clone(falconSig)
	badFalcon[len(badFalcon)-1] ^= 1
	oversized := append(bytes.Clone(falconSig), make([]byte, falconparams.CompressedSignatureMaxSize)...)
	for _, tt := range []struct {
		name               string
		msg, ed, falconSig []byte
		want               string
	}{
		{"other message", other, edSig, falconSig, "Ed25519"},
		{"tampered Ed25519 signature", msg, badEd, falconSig, "Ed25519"},
		{"tampered Falcon signature", msg, edSig, badFalcon, "Falcon"},
		{"oversized Falcon signature", msg, edSig, oversized, "maximum"},
		{"short message", msg[:31], edSig, falconSig, "32-byte"},
	} {
		if err := VerifyClassical(&edKey, &falconKey, tt.msg, tt.ed, tt.falconSig); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
	if err := VerifyClassical(nil, &falconKey, msg, edSig, falconSig); err == nil {
		t.Error("nil public keys verified")
	}
}

func TestSignRefusesOtherMessageSizes(t *testing.T) {
	k, err := DeriveClassicalKeys(testDeriver(t), 0, testEd25519Tag, testFalconTag)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zero()
	for _, n := range []int{0, 31, 33, 64} {
		if ed, falconSig, err := k.Sign(make([]byte, n)); err == nil || ed != nil || falconSig != nil {
			t.Errorf("%d-byte message: signatures %d and %d bytes, err %v", n, len(ed), len(falconSig), err)
		}
	}
}

// TestSignFailureReturnsNoBuffers makes Falcon signing fail, as a zeroed
// Falcon key does, and checks that Sign returns no signature.
func TestSignFailureReturnsNoBuffers(t *testing.T) {
	k, err := DeriveClassicalKeys(testDeriver(t), 0, testEd25519Tag, testFalconTag)
	if err != nil {
		t.Fatal(err)
	}
	k.Zero()
	ed, falconSig, err := k.Sign(testMessage())
	if err == nil || ed != nil || falconSig != nil {
		t.Fatalf("signatures %d and %d bytes, err %v: want a failure and no buffers", len(ed), len(falconSig), err)
	}
}

func TestZeroIsSafeAndComplete(t *testing.T) {
	var none *ClassicalKeys
	none.Zero()
	k, err := DeriveClassicalKeys(testDeriver(t), 0, testEd25519Tag, testFalconTag)
	if err != nil {
		t.Fatal(err)
	}
	k.Zero()
	k.Zero()
	if !allZero(k.ed25519) || !allZero(k.falcon.PrivateKey[:]) {
		t.Fatal("Zero left private key bytes behind")
	}
}

func TestOpenTestMessage(t *testing.T) {
	want := sha256.Sum256([]byte("APLANE_ROTATING_TRIPLE_V1 stage open test"))
	if got := OpenTestMessage("APLANE_ROTATING_TRIPLE_V1"); !bytes.Equal(got, want[:]) {
		t.Fatalf("open-test message %x, want %x", got, want)
	}
	if err := CheckMessage(OpenTestMessage("any label")); err != nil {
		t.Fatal(err)
	}
}

func TestZeroArgs(t *testing.T) {
	args := [][]byte{{1, 2}, nil, {3}}
	ZeroArgs(args)
	if !allZero(args[0]) || !allZero(args[2]) {
		t.Fatal("ZeroArgs left bytes behind")
	}
}
