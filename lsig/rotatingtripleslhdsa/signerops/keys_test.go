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
	"github.com/aplane-algo/aplane/internal/rotatingkey"
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
		"edpk0":            "a8ea95fbe0637982c4ed92a1dcaa9666415883ac0a5b544f111898f3740838cc",
		"edpk1":            "26cd52e32a0aa31eb965fd930319d90a3d7c7abbd2099eab007ad8251a7eefe1",
		"falconpk0_sha256": "cd8b90d6a94325c70ead9ecbf9c30c4ee2f969a0cd151f98b2503eddc999c4a6",
		"falconpk1_sha256": "7323d913dfe7d16ad212f95dc2693bc0e43ad4c776e07f9c1872c79a44e4a692",
		"seed0":            "be00c386124f884ac7377a9f998b0b57",
		"seed1":            "3cf58bc2a2c080d535ed14b320b918be",
	}
	// The root and the address follow from the hypertree height the binary
	// is built with (rotatingkey.RotatingSlhdsaHeight); the seeds and the other keys do not.
	perHeight := map[int]map[string]string{
		22: {
			"address0": "UVL3MPUS3YTDF3YSVHNWN3UIQJGJ4OID6AIAEBN3MJLYAQFDD5ENE3FYHY",
			"address1": "4XAAICKAIZGVIBICGTS6W5G6EFITXXQSNMT4RUCSSH43PTFYIAN53SXK7I",
			"root0":    "f40694d057c49e160c9c90f9bdde6efa",
			"root1":    "56c1a8427638ca8bbca6417adf664669",
		},
		63: {
			"address0": "PGDSQUZ7TMOZ5DHTC64M4INDEF4I7QENPBZP7VB64YVEERMLGNE4IAYOVI",
			"address1": "QYEHV4I3BKJWSRYN2XMFOC6MF3U2VKTIZV4RHKKB7GOG4ZFOBQECXAWKNM",
			"root0":    "51bac26d0f1882e7dae410f99da1416d",
			"root1":    "d072fbc3c66c462f50aabc86ff38215f",
		},
	}
	for k, v := range perHeight[rotatingkey.RotatingSlhdsaHeight] {
		want[k] = v
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
	chunks := len(stage.ChunkSizes)
	if program.Address != a1 || len(sig.Args) != chunks+2 {
		t.Fatal("signature program is not stage 1 or has the wrong argument count")
	}
	total := 0
	var slhSig []byte
	for i, n := range stage.ChunkSizes {
		if len(sig.Args[i]) != n {
			t.Fatalf("argument %d is %d bytes, want %d", i, len(sig.Args[i]), n)
		}
		slhSig = append(slhSig, sig.Args[i]...)
		total += n
	}
	edSig, falconSig := sig.Args[chunks], sig.Args[chunks+1]
	if len(edSig) != stage.Ed25519SignatureSize || len(falconSig) > stage.FalconSignatureMaxSize {
		t.Fatalf("Ed25519 %d bytes, Falcon %d bytes", len(edSig), len(falconSig))
	}
	if total+len(edSig)+len(falconSig) > stage.MaxArgumentBytes {
		t.Fatal("arguments exceed the declared maximum")
	}
	if err := Verify(keys, msg, slhSig, edSig, falconSig); err != nil {
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
	for _, secret := range [][]byte{k.slh.SKSeed[:], k.slh.SKPrf[:]} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("secret not erased")
		}
	}
	// The Ed25519 and Falcon-1024 keys are stagesign's; a zeroed Falcon key
	// cannot sign, and stagesign's own test checks every byte.
	if _, _, err := k.classical.Sign(bytes.Repeat([]byte{3}, 32)); err == nil {
		t.Fatal("the stage's Ed25519 and Falcon keys survived Zero")
	}
}
