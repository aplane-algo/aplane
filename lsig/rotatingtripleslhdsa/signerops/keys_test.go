// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
)

func fixedSeed() (rotatinghybrid.Seed, [rotatinghybrid.GenesisHashSize]byte) {
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for i := range genesis {
		genesis[i] = byte(0xA0 + i)
	}
	return seed, genesis
}

func fixedDeriver(t *testing.T) *rotatinghybrid.Deriver {
	t.Helper()
	seed, genesis := fixedSeed()
	defer seed.Zero()
	d, err := NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestGoldenVectors pins the derivation that fixes every account's identity.
// Changing any of these values is a new key type.
func TestGoldenVectors(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	got := map[string]string{}
	for _, i := range []uint64{0, 1} {
		keys, program, err := DeriveStage(d, i)
		if err != nil {
			t.Fatal(err)
		}
		pub := keys.PublicKeys()
		keys.Zero()
		falconHash := sha256.Sum256(pub.Falcon[:])
		n := string(rune('0' + i))
		got["seed"+n] = hex.EncodeToString(pub.Seed[:])
		got["root"+n] = hex.EncodeToString(pub.Root[:])
		got["edpk"+n] = hex.EncodeToString(pub.Ed25519[:])
		got["falconpk"+n+"_sha256"] = hex.EncodeToString(falconHash[:])
		got["address"+n] = program.Address.String()
		if program.Salted != (len(program.Bytecode) == stage.SaltedProgramSize) {
			t.Fatal("salt flag disagrees with program size")
		}
	}
	want := map[string]string{
		"address0":         "T3DTKVRZHFKYNIRHXN5RWY6SCXXCI7GG3TPJPB7FIFVXG2HPARBVYQM5UM",
		"address1":         "SYYE6APY3XCQPLP3K5LF7JVPR66C2JBABXIBZ4OVAAEFX2I7PZTBD6TEJ4",
		"edpk0":            "a8ea95fbe0637982c4ed92a1dcaa9666415883ac0a5b544f111898f3740838cc",
		"edpk1":            "26cd52e32a0aa31eb965fd930319d90a3d7c7abbd2099eab007ad8251a7eefe1",
		"falconpk0_sha256": "cd8b90d6a94325c70ead9ecbf9c30c4ee2f969a0cd151f98b2503eddc999c4a6",
		"falconpk1_sha256": "7323d913dfe7d16ad212f95dc2693bc0e43ad4c776e07f9c1872c79a44e4a692",
		"root0":            "51bac26d0f1882e7dae410f99da1416d",
		"root1":            "d072fbc3c66c462f50aabc86ff38215f",
		"seed0":            "be00c386124f884ac7377a9f998b0b57",
		"seed1":            "3cf58bc2a2c080d535ed14b320b918be",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}

}

func TestStagesDifferAndSignaturesVerify(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	k0, p0, err := DeriveStage(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer k0.Zero()
	k1, p1, err := DeriveStage(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer k1.Zero()
	if p0.Address == p1.Address || *k0.PublicKeys() == *k1.PublicKeys() {
		t.Fatal("stages 0 and 1 coincide")
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	w, e, f, err := k0.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	embedded, _, err := stage.Parse(p0.Bytecode)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(embedded, msg, w, e, f); err != nil {
		t.Fatal(err)
	}
	if Verify(k1.PublicKeys(), msg, w, e, f) == nil {
		t.Fatal("stage 0 signature verified under stage 1")
	}
	// Each of the three signatures is checked: one from another stage fails.
	w1, e1, f1, err := k1.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][3][]byte{
		"SLH-DSA": {w1, e, f},
		"Ed25519": {w, e1, f},
		"Falcon":  {w, e, f1},
	} {
		if Verify(embedded, msg, args[0], args[1], args[2]) == nil {
			t.Fatalf("stage 1 %s signature verified under stage 0", name)
		}
	}
	if Verify(embedded, msg, w, e, append(bytes.Clone(f), make([]byte, stage.FalconSignatureMaxSize)...)) == nil {
		t.Fatal("oversized Falcon signature accepted")
	}
}

func TestStageOpsThroughKeyMaterial(t *testing.T) {
	var seed rotatinghybrid.Seed
	defer seed.Zero()
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	genesis := bytes.Repeat([]byte{7}, 32)
	key := &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis}
	ops := StageOps{}
	a0, err := ops.StageAddress(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := ops.StageAddress(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a0 == a1 {
		t.Fatal("stage addresses coincide")
	}
	if err := ops.CheckStageOpens(key, 1); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 32)
	sig, err := ops.SignStage(key, 1, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	keys, program, err := stage.Parse(sig.Program)
	if err != nil {
		t.Fatal(err)
	}
	if program.Address != a1 || len(sig.Args) != 5 {
		t.Fatal("signature program is not stage 1 or has the wrong argument count")
	}
	if len(sig.Args[0])+len(sig.Args[1])+len(sig.Args[2])+len(sig.Args[3])+len(sig.Args[4]) > stage.MaxArgumentBytes {
		t.Fatal("arguments exceed the declared maximum")
	}
	if err := Verify(keys, msg, append(append(append([]byte{}, sig.Args[0]...), sig.Args[1]...), sig.Args[2]...), sig.Args[3], sig.Args[4]); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.SignStage(&signing.RotatingKeyMaterial{Seed: seed[:5]}, 0, 0, msg); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestSameStageSignsDifferentMessagesAndZeroesSecrets(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	k, _, err := DeriveStage(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zero()
	for _, msg := range [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)} {
		h, e, f, err := k.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(k.PublicKeys(), msg, h, e, f); err != nil {
			t.Fatal(err)
		}
		msg[0] ^= 1
		if Verify(k.PublicKeys(), msg, h, e, f) == nil {
			t.Fatal("signature accepted a different message")
		}
	}
	k.Zero()
	for _, secret := range [][]byte{k.slh.SKSeed[:], k.slh.SKPrf[:], k.ed25519, k.falcon.PrivateKey[:]} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("secret not erased")
		}
	}
}
