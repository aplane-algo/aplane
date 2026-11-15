// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/aplane-algo/aplane/internal/rotatingstage"
)

// fixedKeys are deterministic keys for stage n, so the tests below see the
// same programs on every run.
func fixedKeys(n uint64) *PublicKeys {
	keys := &PublicKeys{Stage: n}
	for i := range keys.Ed25519 {
		keys.Ed25519[i], keys.Root[i], keys.Seed[i] = byte(3*i+1), byte(5*i+2), byte(7*i+3)
	}
	for i := range keys.Falcon {
		keys.Falcon[i] = byte(11*i + 4)
	}
	_, keys.Lo, keys.Hi = RangeFor(n)
	return keys
}

// TestStageRoundTrip builds stages with small and large numbers and requires
// Parse to return each number, from the prefix every stage program opens with.
func TestStageRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 418, StagesPerTree, 1 << 40, math.MaxUint64} {
		keys := fixedKeys(n)
		program, err := Build(keys)
		if err != nil {
			t.Fatalf("stage %d: %v", n, err)
		}
		got, parsed, err := Parse(program.Bytecode)
		if err != nil {
			t.Fatalf("stage %d: %v", n, err)
		}
		if got.Stage != n || *got != *keys || parsed.Address != program.Address {
			t.Fatalf("stage %d parsed as stage %d", n, got.Stage)
		}
		if embedded, err := rotatingstage.ReadStage(program.Bytecode); err != nil || embedded != n {
			t.Fatalf("stage %d: the prefix reads %d, %v", n, embedded, err)
		}
	}
}

// TestStageNumberChangesTheAddress builds two programs that differ only in
// their stage number: stages a tree apart share a leaf range.
func TestStageNumberChangesTheAddress(t *testing.T) {
	a, err := Build(fixedKeys(418))
	if err != nil {
		t.Fatal(err)
	}
	other := fixedKeys(418)
	other.Stage += StagesPerTree
	b, err := Build(other)
	if err != nil {
		t.Fatal(err)
	}
	if a.Address == b.Address {
		t.Fatal("stages 418 and 1442 with the same keys and range have one address")
	}
	ua, ub := a.Bytecode[:UnsaltedProgramSize], b.Bytecode[:UnsaltedProgramSize]
	for i := range ua {
		inStage := i >= rotatingstage.StageOffset && i < rotatingstage.StageOffset+rotatingstage.StageSize
		if ua[i] != ub[i] && !inStage {
			t.Fatalf("the programs differ at %d, outside the stage number", i)
		}
	}
}

// TestBuildRefusesARangeThatIsNotTheStages requires Lo and Hi to be the
// stage's own range.
func TestBuildRefusesARangeThatIsNotTheStages(t *testing.T) {
	keys := fixedKeys(418)
	keys.Stage++
	if _, err := Build(keys); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("stage 419 with stage 418's range: %v", err)
	}
}

// TestAlteredStageByte changes one byte of the stage number. Parse rebuilds
// the program from the constants it embeds, so the altered bytes never parse
// as the original stage or with its address: they parse as the stage they now
// name when Build of that stage gives exactly these bytes, and are refused
// otherwise, for a range that is not the new stage's or a salt that no
// longer fits. Both happen among these alterations.
func TestAlteredStageByte(t *testing.T) {
	for _, n := range []uint64{0, 418} {
		keys := fixedKeys(n)
		original, err := Build(keys)
		if err != nil {
			t.Fatal(err)
		}
		parsedAsOther, refused := 0, 0
		for off := rotatingstage.StageOffset; off < rotatingstage.StageOffset+rotatingstage.StageSize; off++ {
			for _, flip := range []byte{0x01, 0x04, 0x80} {
				tampered := bytes.Clone(original.Bytecode)
				tampered[off] ^= flip
				altered := *keys
				altered.Stage = binary.BigEndian.Uint64(tampered[rotatingstage.StageOffset:])
				want, buildErr := Build(&altered)
				got, parsed, err := Parse(tampered)
				if err == nil && (got.Stage == n || parsed.Address == original.Address) {
					t.Fatalf("stage %d altered at %d parsed as the original stage", n, off)
				}
				if buildErr == nil && bytes.Equal(want.Bytecode, tampered) {
					if err != nil || got.Stage != altered.Stage || parsed.Address != want.Address {
						t.Fatalf("stage %d altered at %d: want stage %d, got %v", n, off, altered.Stage, err)
					}
					parsedAsOther++
					continue
				}
				if !errors.Is(err, ErrInvalidProgram) {
					t.Fatalf("stage %d altered at %d was not refused: %v", n, off, err)
				}
				refused++
			}
		}
		if parsedAsOther == 0 || refused == 0 {
			t.Fatalf("stage %d: %d alterations parsed as another stage and %d were refused; want some of each", n, parsedAsOther, refused)
		}
	}
}
