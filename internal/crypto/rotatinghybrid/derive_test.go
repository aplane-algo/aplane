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

const testLabel = "APLANE_ROTATING_TEST"

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
	d, err := NewDeriverWithLabel(&seed, genesis, testLabel)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zero()

	for _, stage := range []uint64{0, 1, 2, 1 << 40} {
		got := make([]byte, FalconSeedSize)
		if err := d.ExpandStage(0x01, stage, got); err != nil {
			t.Fatalf("ExpandStage(%d) error = %v", stage, err)
		}
		info := append([]byte{0x01}, genesis[:]...)
		want, _ := hkdf.Key(sha512.New, seed[:], []byte(testLabel), string(binary.BigEndian.AppendUint64(info, stage)), FalconSeedSize)
		if !bytes.Equal(got, want) {
			t.Fatalf("ExpandStage(%d) does not match the documented derivation", stage)
		}
	}
}

func TestStageSeedsAreIndependent(t *testing.T) {
	seed, err := SeedFromMnemonic(testWords())
	if err != nil {
		t.Fatal(err)
	}
	expand := func(genesis [GenesisHashSize]byte, tag byte, i uint64) [Ed25519SeedSize]byte {
		d, err := NewDeriverWithLabel(&seed, genesis, testLabel)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Zero()
		var out [Ed25519SeedSize]byte
		if err := d.ExpandStage(tag, i, out[:]); err != nil {
			t.Fatal(err)
		}
		return out
	}

	base := expand(testGenesis(1), 1, 0)
	if base != expand(testGenesis(1), 1, 0) {
		t.Fatal("derivation is not deterministic")
	}
	if base == expand(testGenesis(1), 1, 1) {
		t.Fatal("adjacent stages share seeds")
	}
	if base == expand(testGenesis(2), 1, 0) {
		t.Fatal("different networks share seeds")
	}
	if base == expand(testGenesis(1), 2, 0) {
		t.Fatal("two tags share seeds")
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
	d, err := NewDeriverWithLabel(&seed, testGenesis(0), testLabel)
	if err != nil {
		t.Fatal(err)
	}
	prk := d.prk
	d.Zero()
	if !bytes.Equal(prk, make([]byte, len(prk))) {
		t.Fatal("Zero() left PRK bytes behind")
	}
	if err := d.ExpandStage(1, 0, make([]byte, 32)); err == nil {
		t.Fatal("ExpandStage() after Zero() succeeded")
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
