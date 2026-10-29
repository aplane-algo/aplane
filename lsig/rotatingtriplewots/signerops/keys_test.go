// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
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
