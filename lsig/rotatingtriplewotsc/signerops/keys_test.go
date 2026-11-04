// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
)

func testDeriver(t *testing.T, seedByte, genesisByte byte) *rotatinghybrid.Deriver {
	t.Helper()
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = seedByte
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for i := range genesis {
		genesis[i] = genesisByte
	}
	d, err := NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Zero)
	return d
}

func deriveStage(t *testing.T, d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program) {
	t.Helper()
	keys, program, err := DeriveStage(d, i)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Zero)
	return keys, program
}

func TestDerivationIsRepeatableAndSeparated(t *testing.T) {
	d := testDeriver(t, 1, 2)
	_, first := deriveStage(t, d, 5)
	_, again := deriveStage(t, testDeriver(t, 1, 2), 5)
	if !bytes.Equal(first.Bytecode, again.Bytecode) {
		t.Fatal("the same seed, genesis and stage gave different programs")
	}
	for name, other := range map[string]*rotatinghybrid.Deriver{
		"seed":    testDeriver(t, 3, 2),
		"genesis": testDeriver(t, 1, 4),
	} {
		_, program := deriveStage(t, other, 5)
		if program.Address == first.Address {
			t.Fatalf("a different %s gave the same stage", name)
		}
	}
	if _, next := deriveStage(t, d, 6); next.Address == first.Address {
		t.Fatal("two stages share an address")
	}
}

// The seeds must be independent values: a tag collision would reuse one as the
// other without any test of the signature noticing.
func TestStageSeedsAreDistinct(t *testing.T) {
	keys, _ := deriveStage(t, testDeriver(t, 1, 2), 0)
	seen := map[[wotsc.N]byte]bool{keys.hash.SKSeed: true, keys.hash.SKPrf: true, keys.hash.Public.Seed: true}
	if len(seen) != 3 {
		t.Fatal("two derived seeds are equal")
	}
}

func TestSignVerifyAcrossLeaves(t *testing.T) {
	keys, program := deriveStage(t, testDeriver(t, 7, 8), 3)
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		t.Fatal(err)
	}
	message := sha256.Sum256([]byte("transaction"))
	other := sha256.Sum256([]byte("other transaction"))
	for _, leaf := range []uint32{0, 1, 31, 63} {
		hashSig, edSig, falconSig, err := keys.Sign(leaf, message[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(embedded, message[:], hashSig, edSig, falconSig); err != nil {
			t.Fatalf("leaf %d: %v", leaf, err)
		}
		if err := Verify(embedded, other[:], hashSig, edSig, falconSig); err == nil {
			t.Fatalf("leaf %d: verified another message", leaf)
		}
	}
	if _, _, _, err := keys.Sign(wotsc.Leaves, message[:]); err == nil {
		t.Fatal("signed with a leaf outside the tree")
	}
	if _, _, _, err := keys.Sign(0, []byte("short")); err == nil {
		t.Fatal("signed a message that is not a TxID")
	}
}

func TestZero(t *testing.T) {
	keys, _ := deriveStage(t, testDeriver(t, 9, 9), 0)
	keys.Zero()
	if keys.hash.SKSeed != ([wotsc.N]byte{}) || keys.hash.SKPrf != ([wotsc.N]byte{}) {
		t.Fatal("hash seeds not erased")
	}
	var nilKeys *StageKeys
	nilKeys.Zero()
}

func BenchmarkDeriveStage(b *testing.B) {
	var seed rotatinghybrid.Seed
	var genesis [rotatinghybrid.GenesisHashSize]byte
	d, err := NewDeriver(&seed, genesis)
	if err != nil {
		b.Fatal(err)
	}
	defer d.Zero()
	var stageIndex uint64
	for b.Loop() {
		keys, _, err := DeriveStage(d, stageIndex)
		if err != nil {
			b.Fatal(err)
		}
		keys.Zero()
		stageIndex++
	}
}

func BenchmarkSignStage(b *testing.B) {
	var seed rotatinghybrid.Seed
	var genesis [rotatinghybrid.GenesisHashSize]byte
	d, err := NewDeriver(&seed, genesis)
	if err != nil {
		b.Fatal(err)
	}
	defer d.Zero()
	keys, _, err := DeriveStage(d, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer keys.Zero()
	message := sha256.Sum256([]byte("benchmark"))
	for b.Loop() {
		if _, _, _, err := keys.Sign(7, message[:]); err != nil {
			b.Fatal(err)
		}
	}
}
