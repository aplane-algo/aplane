// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/stage"
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

var (
	fixedTreesOnce sync.Once
	fixedTrees     [2]*PublicTree
)

// fixedTree builds trees 0 and 1 of the fixed seed once per test binary.
func fixedTree(t *testing.T, n uint64) *PublicTree {
	t.Helper()
	fixedTreesOnce.Do(func() {
		d := fixedDeriver(t)
		defer d.Zero()
		for i := range fixedTrees {
			tr, err := GenerateTree(d, uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			fixedTrees[i] = tr
		}
	})
	return fixedTrees[n]
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
	for n := range uint64(2) {
		tr := fixedTree(t, n)
		got["root"+string(rune('0'+n))] = hex.EncodeToString(tr.PK.Root[:])
		got["seed"+string(rune('0'+n))] = hex.EncodeToString(tr.PK.Seed[:])
	}
	for _, i := range []uint64{0, 1, stage.StagesPerTree - 1, stage.StagesPerTree} {
		treeNo, _, _ := stage.RangeFor(i)
		keys, program, err := DeriveStage(d, i, fixedTree(t, treeNo))
		if err != nil {
			t.Fatal(err)
		}
		pub := keys.PublicKeys()
		keys.Zero()
		falconHash := sha256.Sum256(pub.Falcon[:])
		name := map[uint64]string{0: "0", 1: "1", stage.StagesPerTree - 1: "1023", stage.StagesPerTree: "1024"}[i]
		got["edpk"+name] = hex.EncodeToString(pub.Ed25519[:])
		got["falconpk"+name+"_sha256"] = hex.EncodeToString(falconHash[:])
		got["address"+name] = program.Address.String()
		if program.Salted != (len(program.Bytecode) == stage.SaltedProgramSize) {
			t.Fatal("salt flag disagrees with program size")
		}
	}
	want := map[string]string{
		"tag":                 "4c6faaf30d3a8228863a003560643dc5c622bffab7d65f426c0fdbc942cc0b2e",
		"root0":               "4bf9170fbf2cea2030401eeaaa5d2c9e4004ce5846dacd09b502f0b4ee9d182c",
		"seed0":               "e8541470a79c79d2a6d748270a12ba3dd47db8071fd36036155a511c2075b7a2",
		"root1":               "44a7a9582150d0e9195e52ed4434dddc2d8316648821da2c0748bdaa8b6dcd92",
		"seed1":               "bc6b34a6257fc6e93dc8915db1189aabcc2c5d3d7c3172cacd23d4942d817396",
		"edpk0":               "35c1b2f513e7a47b1995b4f8d724ae3d63eb7c42b8ddae9c487999b8dd21304c",
		"falconpk0_sha256":    "30a199f200e8e916ee79211f112160f68c68e46688918513709ec6ddcda016bb",
		"address0":            "UIZ55YVZTGO2QU4MFWH5CZJHGKZSL3BDYJLHAIPYTQ77YHAYPHDR6IPFR4",
		"edpk1":               "85318ccd595b6c023a990afa636a8296e8eadf9ee978efbe004c41a85a6dccec",
		"falconpk1_sha256":    "ea81779f4444f02e65099e7552871c986898fed8ef325661345c7ed007604dcb",
		"address1":            "75NMZBKGDXZ6DCEX5V33AIRDS6AIVC3KGMFSIXW6FF7QJ7UOULS2WQQZ2Q",
		"edpk1023":            "36bd81446af93fd3108a7b109f18c91cf52b763f5db6023197692755614e1083",
		"falconpk1023_sha256": "2ce67a0fb5d5a60304e9e673d905e907bd4a074f19d3b32076f236b7882ad58a",
		"address1023":         "FN6J5CEOXTLKTEVZC5QUXLTFAPNCWBGTYRAVWOBXE3MH4HOQB24HVRPYMQ",
		"edpk1024":            "06b25e171126300e16c499988ddd2cf7ed6906a4d506412cfa646db53f37bb03",
		"falconpk1024_sha256": "35f3bb4176ad8589375fbf608fda7c9b2d7803da03c15b97317e3333595d1f14",
		"address1024":         "3SJVTNHAAQY3YAGKFO7YISKY2HHCRDJFG6YGG7LQ356XMIAXCANAKAZEFA",
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

// The same seed is a different account on another network: every tree
// seed differs, so every root does.
func TestNetworkBindsTreeSeeds(t *testing.T) {
	seed, genesis := fixedSeed()
	other := genesis
	other[0] ^= 1
	d1, err := NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer d1.Zero()
	d2, err := NewDeriver(&seed, other)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Zero()
	s1, err := TreeSeeds(d1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Zero()
	s2, err := TreeSeeds(d2, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Zero()
	if s1.SKSeed == s2.SKSeed || s1.SKPRF == s2.SKPRF || s1.PubSeed == s2.PubSeed {
		t.Fatal("tree seeds coincide across networks")
	}
	// And tree 1's seeds differ from tree 0's on the same network.
	s3, err := TreeSeeds(d1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Zero()
	if s1.SKSeed == s3.SKSeed || s1.PubSeed == s3.PubSeed {
		t.Fatal("tree 0 and tree 1 seeds coincide")
	}
}

func TestStagesDifferAndSignaturesVerify(t *testing.T) {
	d := fixedDeriver(t)
	defer d.Zero()
	tr := fixedTree(t, 0)
	k0, p0, err := DeriveStage(d, 0, tr)
	if err != nil {
		t.Fatal(err)
	}
	defer k0.Zero()
	k1, p1, err := DeriveStage(d, 1, tr)
	if err != nil {
		t.Fatal(err)
	}
	defer k1.Zero()
	if p0.Address == p1.Address || *k0.PublicKeys() == *k1.PublicKeys() {
		t.Fatal("stages 0 and 1 coincide")
	}
	if lo, hi := k1.Range(); lo != stage.IndicesPerStage || hi != 2*stage.IndicesPerStage {
		t.Fatalf("stage 1 range [%d, %d)", lo, hi)
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	x, e, f, err := k0.Sign(msg, 3)
	if err != nil {
		t.Fatal(err)
	}
	embedded, _, err := stage.Parse(p0.Bytecode)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(embedded, msg, x, e, f); err != nil {
		t.Fatal(err)
	}
	if Verify(k1.PublicKeys(), msg, x, e, f) == nil {
		t.Fatal("stage 0 signature verified under stage 1")
	}
	// A leaf outside the stage's range is refused at signing and, if it
	// were signed with, at verification.
	if _, _, _, err := k0.Sign(msg, stage.IndicesPerStage); err == nil {
		t.Fatal("stage 0 signed with stage 1's leaf")
	}
	x1, e1, f1, err := k1.Sign(msg, stage.IndicesPerStage)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(embedded, msg, x1, e, f) == nil {
		t.Fatal("stage 1's leaf verified under stage 0's program")
	}
	for name, args := range map[string][3][]byte{
		"Ed25519": {x, e1, f},
		"Falcon":  {x, e, f1},
	} {
		if Verify(embedded, msg, args[0], args[1], args[2]) == nil {
			t.Fatalf("stage 1 %s signature verified under stage 0", name)
		}
	}
	if Verify(embedded, msg, x, e, append(bytes.Clone(f), make([]byte, stage.FalconSignatureMaxSize)...)) == nil {
		t.Fatal("oversized Falcon signature accepted")
	}
	if Verify(embedded, msg, x[:10], e, f) == nil {
		t.Fatal("truncated XMSS signature accepted")
	}
	if _, _, err := DeriveStage(d, stage.StagesPerTree, tr); err == nil {
		t.Fatal("stage 1024 derived from tree 0")
	}
}

func TestStageOpsThroughKeyMaterial(t *testing.T) {
	seed, genesis := fixedSeed()
	key := &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis[:]}
	ops := NewStageOps()
	// Seed the cache with the trees the test binary already built.
	d := fixedDeriver(t)
	tag, err := AccountTag(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Zero()
	for n := range uint64(2) {
		ops.trees[treeKey{tag: tag, genesis: genesis, tree: n}] = fixedTree(t, n)
	}
	a0, err := ops.StageAddress(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := ops.StageAddress(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a0 == a1 {
		t.Fatal("stages 0 and 1 share an address")
	}
	if err := ops.CheckStageOpens(key, 1); err != nil {
		t.Fatal(err)
	}
	if err := ops.CheckStageOpens(key, stage.StagesPerTree); err != nil {
		t.Fatalf("stage 1024 (tree 1): %v", err)
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	sig, err := ops.SignStage(key, 1, stage.IndicesPerStage+5, msg)
	if err != nil {
		t.Fatal(err)
	}
	embedded, program, err := stage.Parse(sig.Program)
	if err != nil {
		t.Fatal(err)
	}
	if program.Address != a1 || len(sig.Args) != 3 {
		t.Fatalf("signature program %s, %d args", program.Address, len(sig.Args))
	}
	if err := Verify(embedded, msg, sig.Args[0], sig.Args[1], sig.Args[2]); err != nil {
		t.Fatal(err)
	}
	if idx, _ := xmss.Index(sig.Args[0]); idx != stage.IndicesPerStage+5 {
		t.Fatalf("signature names leaf %d", idx)
	}
	if _, err := ops.SignStage(key, 1, 0, msg); err == nil {
		t.Fatal("stage 1 signed with leaf 0")
	}
	if got := ops.CachedTrees(); got != 2 {
		t.Fatalf("cached trees = %d, want 2", got)
	}
	if err := ops.Forget(key); err != nil {
		t.Fatal(err)
	}
	if got := ops.CachedTrees(); got != 0 {
		t.Fatalf("cached trees after Forget = %d", got)
	}
	if _, err := ops.SignStage(&signing.RotatingKeyMaterial{Seed: seed[:5]}, 0, 0, msg); err == nil {
		t.Fatal("short seed accepted")
	}
}

// A tree requested by several goroutines at once is generated once.
func TestTreeGenerationIsShared(t *testing.T) {
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	genesis := bytes.Repeat([]byte{9}, 32)
	key := &signing.RotatingKeyMaterial{Seed: seed[:], GenesisHash: genesis}
	ops := NewStageOps()
	var wg sync.WaitGroup
	addrs := make([]string, 4)
	for i := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := ops.StageAddress(key, 0)
			if err != nil {
				t.Error(err)
				return
			}
			addrs[i] = a.String()
		}()
	}
	wg.Wait()
	for _, a := range addrs[1:] {
		if a != addrs[0] {
			t.Fatal("concurrent derivations disagree")
		}
	}
	if got := ops.CachedTrees(); got != 1 {
		t.Fatalf("cached trees = %d, want 1", got)
	}
	if err := ops.Prepare(key, 0); err != nil {
		t.Fatal(err)
	}
	if got := ops.CachedTrees(); got != 1 {
		t.Fatalf("Prepare of a cached tree changed the cache to %d", got)
	}
}
