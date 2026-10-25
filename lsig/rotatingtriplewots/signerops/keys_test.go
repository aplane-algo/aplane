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
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewots/stage"
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
	tag, err := AccountTag(d)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{"tag": hex.EncodeToString(tag[:])}
	for _, i := range []uint64{0, 1} {
		keys, program, err := DeriveStage(d, i)
		if err != nil {
			t.Fatal(err)
		}
		pub := keys.PublicKeys()
		keys.Zero()
		falconHash := sha256.Sum256(pub.Falcon[:])
		n := string(rune('0' + i))
		got["tweak"+n] = hex.EncodeToString(pub.Tweak[:])
		got["wotspk"+n] = hex.EncodeToString(pub.Wots[:])
		got["edpk"+n] = hex.EncodeToString(pub.Ed25519[:])
		got["falconpk"+n+"_sha256"] = hex.EncodeToString(falconHash[:])
		got["address"+n] = program.Address.String()
		if program.Salted != (len(program.Bytecode) == stage.SaltedProgramSize) {
			t.Fatal("salt flag disagrees with program size")
		}
	}
	want := map[string]string{
		"tag":              "2b2ef4d059822fe5c1b60913950bb5d2b2eb9dcdb9ad247733722957d039a0a5",
		"tweak0":           "87841f4ce3cb20ac09afa9dfba448024eeb6841f956d23287957c59e22dc6030",
		"wotspk0":          "4fb6ef82f315cc5491130b11292ee66df64bcbec8a3c2c0afbe10137b88cfdcf",
		"edpk0":            "5eda254ea0cab100fea3e393a46fea68e6bb88eff7ca0a5544774ff84ca9e9f5",
		"falconpk0_sha256": "1eaee1fa0ea59c32fb8a7327c10a8e7ca73b6c919c4a94f5eb0cd81104f47662",
		"address0":         "YX62PQ4VBCVBAA5577SHXSYDYCC6DMYOUTUVPVN4QTSIZQ6KVPFVCC64XA",
		"tweak1":           "86a5febc6bab3e4222c3a641b9a8b9498827689d6e9cd65a76d7bd80a3792cf6",
		"wotspk1":          "9e1a0ef3ce930d65a7097f8b0eebd416e8d763073656c33342864913fb1c1b32",
		"edpk1":            "1da58ca741e2cdb556d13929fc60d633c00dc0a67bcc4f2eaca4af589fea8f2e",
		"falconpk1_sha256": "576982f151d59906bcca32bc14ae8f5d87a8ae630b89afd873c4d477c0e2d209",
		"address1":         "B7FOCZLDRRC5I7TRGT3LDKJQBF7P5GW4F4KWNMOGJIKUISTOKQVYWZ5FTI",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d values, want %d", len(got), len(want))
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
		"WOTS":    {w1, e, f},
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
	if program.Address != a1 || len(sig.Args) != 3 {
		t.Fatal("signature program is not stage 1 or has the wrong argument count")
	}
	if len(sig.Args[0])+len(sig.Args[1])+len(sig.Args[2]) > stage.MaxArgumentBytes {
		t.Fatal("arguments exceed the declared maximum")
	}
	if err := Verify(keys, msg, sig.Args[0], sig.Args[1], sig.Args[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.SignStage(&signing.RotatingKeyMaterial{Seed: seed[:5]}, 0, 0, msg); err == nil {
		t.Fatal("short seed accepted")
	}
}
