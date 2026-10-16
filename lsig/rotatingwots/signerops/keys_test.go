// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingwots/stage"
)

func fixedDeriver(t *testing.T) *rotatinghybrid.Deriver {
	t.Helper()
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for i := range genesis {
		genesis[i] = byte(0xA0 + i)
	}
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
	keys, program, err := DeriveStage(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	pub := keys.PublicKeys()
	got := map[string]string{
		"tag":     hex.EncodeToString(tag[:]),
		"tweak0":  hex.EncodeToString(pub.Tweak[:]),
		"wotspk0": hex.EncodeToString(pub.Wots[:]),
		"edpk0":   hex.EncodeToString(pub.Ed25519[:]),
		"address": program.Address.String(),
	}
	want := map[string]string{
		"tag":     "1a691bca894c6488c5581d3c50acf8f5084f2864800156baf5a990d4ba5fa504",
		"tweak0":  "85db68cee7b1867718020119adf15f78ae8994de34e3e73a0ac809ce459e6f56",
		"wotspk0": "a8e1c71c1f7348624bef377450a8ae12115193feaf3600fee2c11f50f0585652",
		"edpk0":   "2664aaa9e14020cee4a03fd6db5b697a669311c5290e41dea2d902ee91e604ba",
		"address": "6T6RC25T7BTMXU2VMMN5E7FJFBJDSVUYFMJ3PVATEB6EEIKJCN2F4SKCAQ",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if program.Salted != (len(program.Bytecode) == stage.SaltedProgramSize) {
		t.Fatal("salt flag disagrees with program size")
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
	if p0.Address == p1.Address || k0.PublicKeys() == k1.PublicKeys() {
		t.Fatal("stages 0 and 1 coincide")
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	w, e, err := k0.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	embedded, _, err := stage.Parse(p0.Bytecode)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(embedded, msg, w, e); err != nil {
		t.Fatal(err)
	}
	if Verify(k1.PublicKeys(), msg, w, e) == nil {
		t.Fatal("stage 0 signature verified under stage 1")
	}
	w1, _, _ := k1.Sign(msg)
	if Verify(embedded, msg, w1, e) == nil {
		t.Fatal("stage 1 WOTS signature verified under stage 0")
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
	sig, err := ops.SignStage(key, 1, msg)
	if err != nil {
		t.Fatal(err)
	}
	keys, program, err := stage.Parse(sig.Program)
	if err != nil {
		t.Fatal(err)
	}
	if program.Address != a1 || len(sig.Args) != 2 {
		t.Fatal("signature program is not stage 1 or has the wrong argument count")
	}
	if err := Verify(keys, msg, sig.Args[0], sig.Args[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.SignStage(&signing.RotatingKeyMaterial{Seed: seed[:5]}, 0, msg); err == nil {
		t.Fatal("short seed accepted")
	}
}
