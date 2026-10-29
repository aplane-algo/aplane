// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatinghybrid

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon art"

func testWords() []string { return strings.Fields(testMnemonic) }

func testGenesis(b byte) [GenesisHashSize]byte {
	var g [GenesisHashSize]byte
	for i := range g {
		g[i] = b + byte(i)
	}
	return g
}

// The falcon-signatures library runs standard BIP-39 PBKDF2 and then one
// HKDF step with its own salt and info. Applying that HKDF step to our seed
// must reproduce its output, which proves our PBKDF2 stage is the standard
// BIP-39 seed.
func TestSeedFromMnemonicIsStandardBIP39Seed(t *testing.T) {
	seed, err := SeedFromMnemonic(testWords())
	if err != nil {
		t.Fatalf("SeedFromMnemonic() error = %v", err)
	}
	want, err := falconmnemonic.SeedFromMnemonic(testWords(), "")
	if err != nil {
		t.Fatalf("falcon SeedFromMnemonic() error = %v", err)
	}
	got, err := hkdf.Key(sha512.New, seed[:], []byte("bip39-falcon-seed-salt-v1"), "Falcon1024 seed v1", len(want))
	if err != nil {
		t.Fatalf("hkdf.Key() error = %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("BIP-39 seed does not match the falcon-signatures derivation")
	}
}

func TestSeedFromMnemonicRejectsInvalidPhrases(t *testing.T) {
	short := testWords()[:12]
	badWord := testWords()
	badWord[3] = "notaword"
	badChecksum := testWords()
	badChecksum[23] = "abandon"

	for name, words := range map[string][]string{
		"short":        short,
		"unknown word": badWord,
		"checksum":     badChecksum,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SeedFromMnemonic(words); !errors.Is(err, ErrInvalidMnemonic) {
				t.Fatalf("SeedFromMnemonic() error = %v, want ErrInvalidMnemonic", err)
			}
		})
	}
}

// Recompute the documented derivation independently of Deriver so a change
// to the info layout or label cannot pass silently.
func TestStageMatchesDocumentedDerivation(t *testing.T) {
	seed, err := SeedFromMnemonic(testWords())
	if err != nil {
		t.Fatal(err)
	}
	genesis := testGenesis(7)
	d, err := NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zero()

	for _, stage := range []uint64{0, 1, 2, 1 << 40} {
		got, err := d.Stage(stage)
		if err != nil {
			t.Fatalf("Stage(%d) error = %v", stage, err)
		}
		info := func(tag byte) string {
			b := append([]byte{tag}, genesis[:]...)
			return string(binary.BigEndian.AppendUint64(b, stage))
		}
		wantFalcon, _ := hkdf.Key(sha512.New, seed[:], []byte(DerivationLabel), info(0x01), FalconSeedSize)
		wantEd, _ := hkdf.Key(sha512.New, seed[:], []byte(DerivationLabel), info(0x02), Ed25519SeedSize)
		if !bytes.Equal(got.Falcon[:], wantFalcon) || !bytes.Equal(got.Ed25519[:], wantEd) {
			t.Fatalf("Stage(%d) does not match the documented derivation", stage)
		}
	}
}

func TestStageSeedsAreIndependent(t *testing.T) {
	seed, err := SeedFromMnemonic(testWords())
	if err != nil {
		t.Fatal(err)
	}
	stage := func(genesis [GenesisHashSize]byte, i uint64) StageSeeds {
		d, err := NewDeriver(&seed, genesis)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Zero()
		s, err := d.Stage(i)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	base := stage(testGenesis(1), 0)
	if base != stage(testGenesis(1), 0) {
		t.Fatal("derivation is not deterministic")
	}
	if base == stage(testGenesis(1), 1) {
		t.Fatal("adjacent stages share seeds")
	}
	if base == stage(testGenesis(2), 0) {
		t.Fatal("different networks share seeds")
	}
	if bytes.Equal(base.Falcon[:Ed25519SeedSize], base.Ed25519[:]) {
		t.Fatal("Falcon and Ed25519 seeds are not domain-separated")
	}
}

func TestOpenDeriverMatchesNewDeriverWithLabel(t *testing.T) {
	seed, err := SeedFromMnemonic(testWords())
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	genesis := testGenesis(1)
	const label = "APLANE_TEST_LABEL"
	want, err := NewDeriverWithLabel(&seed, genesis, label)
	if err != nil {
		t.Fatal(err)
	}
	defer want.Zero()
	stored := bytes.Clone(seed[:])
	got, err := OpenDeriver(stored, genesis[:], label)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zero()
	if !bytes.Equal(stored, seed[:]) {
		t.Fatal("OpenDeriver changed the caller's seed")
	}
	if got.GenesisHash() != genesis {
		t.Fatal("OpenDeriver bound another network")
	}
	var a, b [32]byte
	if err := want.ExpandStage(0x02, 7, a[:]); err != nil {
		t.Fatal(err)
	}
	if err := got.ExpandStage(0x02, 7, b[:]); err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("OpenDeriver derives other stage material than NewDeriverWithLabel")
	}

	for _, tt := range []struct {
		name          string
		seed, genesis []byte
	}{
		{"short seed", stored[:SeedSize-1], genesis[:]},
		{"long seed", append(bytes.Clone(stored), 0), genesis[:]},
		{"short genesis hash", stored, genesis[:GenesisHashSize-1]},
		{"missing genesis hash", stored, nil},
	} {
		if _, err := OpenDeriver(tt.seed, tt.genesis, label); err == nil {
			t.Errorf("%s: OpenDeriver succeeded", tt.name)
		}
	}
	if _, err := OpenDeriver(stored, genesis[:], ""); err == nil {
		t.Error("OpenDeriver accepted an empty label")
	}
}

func TestDeriverZero(t *testing.T) {
	seed, err := SeedFromMnemonic(testWords())
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDeriver(&seed, testGenesis(0))
	if err != nil {
		t.Fatal(err)
	}
	prk := d.prk
	d.Zero()
	if !bytes.Equal(prk, make([]byte, len(prk))) {
		t.Fatal("Zero() left PRK bytes behind")
	}
	if _, err := d.Stage(0); err == nil {
		t.Fatal("Stage() after Zero() succeeded")
	}

	seed.Zero()
	if seed != (Seed{}) {
		t.Fatal("Seed.Zero() left bytes behind")
	}
}

func TestNewMnemonic(t *testing.T) {
	words, seed, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	if len(words) != MnemonicWordCount {
		t.Fatalf("got %d words", len(words))
	}
	again, err := SeedFromMnemonic(words)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Zero()
	if again != seed {
		t.Fatal("returned seed does not derive from the returned words")
	}
	other, otherSeed, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	defer otherSeed.Zero()
	if strings.Join(other, " ") == strings.Join(words, " ") {
		t.Fatal("two calls returned the same mnemonic")
	}
}
