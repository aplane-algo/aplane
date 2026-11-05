// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func randomKeys(t *testing.T) *PublicKeys {
	t.Helper()
	keys := &PublicKeys{}
	for _, b := range [][]byte{keys.Ed25519[:], keys.Falcon[:], keys.Root[:], keys.Seed[:]} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func keysWithSalt(t *testing.T, salted bool) (*PublicKeys, Program) {
	t.Helper()
	for range 256 {
		keys := randomKeys(t)
		program, err := Build(keys)
		if err != nil {
			t.Fatal(err)
		}
		if program.Salted == salted {
			return keys, program
		}
	}
	t.Fatalf("no program with salted=%v in 256 tries", salted)
	return nil, Program{}
}

func TestBuildRejectsNilKeys(t *testing.T) {
	if _, err := Build(nil); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("nil keys: got %v, want ErrInvalidProgram", err)
	}
}

func TestBuildParseRoundTrip(t *testing.T) {
	for _, salted := range []bool{false, true} {
		keys, program := keysWithSalt(t, salted)
		got, parsed, err := Parse(program.Bytecode)
		if err != nil {
			t.Fatalf("salted=%v: %v", salted, err)
		}
		if *got != *keys || parsed.Address != program.Address || parsed.Salted != salted {
			t.Fatalf("salted=%v: round trip mismatch", salted)
		}
		if lsigsalt.IsOnCurve(program.Address) {
			t.Fatal("built program address is on-curve")
		}
	}
}

func TestParseRejectsNonCanonicalPrograms(t *testing.T) {
	_, unsalted := keysWithSalt(t, false)
	_, salted := keysWithSalt(t, true)

	withSalt := append(bytes.Clone(unsalted.Bytecode), opIntcblock, 0x01, 0x00)
	if _, _, err := Parse(withSalt); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("needless salt accepted: %v", err)
	}
	wrongSalt := bytes.Clone(salted.Bytecode)
	wrongSalt[len(wrongSalt)-1]++
	if _, _, err := Parse(wrongSalt); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("wrong salt accepted: %v", err)
	}
	for _, off := range []int{10, falconKeyOffset - 1, seedOffset - 3, UnsaltedProgramSize - 1} {
		tampered := bytes.Clone(unsalted.Bytecode)
		tampered[off] ^= 1
		if _, _, err := Parse(tampered); !errors.Is(err, ErrInvalidProgram) {
			t.Fatalf("template tampered at %d accepted: %v", off, err)
		}
	}
	if _, _, err := Parse(unsalted.Bytecode[:100]); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("short program accepted: %v", err)
	}
}

// TestBuildMatchesStockAssembler compiles TEALSource with a stock algod and
// requires the local template substitution to produce the same bytes.
// Set TEAL_COMPILE_ALGOD_URL to use a local node.
func TestBuildMatchesStockAssembler(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
	if err != nil {
		t.Skipf("algod client: %v", err)
	}
	if err := client.HealthCheck().Do(t.Context()); err != nil {
		t.Skipf("algod unreachable: %v", err)
	}
	for _, salted := range []bool{false, true} {
		keys, want := keysWithSalt(t, salted)
		got := compile(t, TEALSource(keys))
		if !bytes.Equal(got, want.Bytecode) {
			t.Fatalf("salted=%v: local bytecode differs from algod\nlocal: %x\nalgod: %x", salted, want.Bytecode, got)
		}
	}
}

// TestResourceCeiling pins the literals other packages and documents restate:
// program sizes, argument bytes, the opcode ceiling and the group they need.
func TestResourceCeiling(t *testing.T) {
	if wotsc.Len*(wotsc.W-1)-wotsc.TargetSum != ChainSteps {
		t.Fatalf("ChainSteps %d does not follow from the parameters", ChainSteps)
	}
	if UnsaltedProgramSize != 2483 || SaltedProgramSize != 2486 || MaxArgumentBytes != 2115 {
		t.Fatalf("frozen sizes changed: program %d/%d, arguments %d", UnsaltedProgramSize, SaltedProgramSize, MaxArgumentBytes)
	}
	if MaxOpcodeCost != 15721 {
		t.Fatalf("opcode cost %d, want 15721", MaxOpcodeCost)
	}
	byCost := (MaxOpcodeCost + 19999) / 20000
	byArgs := (MaxArgumentBytes + 999) / 1000
	if group := max(byCost, byArgs); group != 3 {
		t.Fatalf("group of %d by cost, %d by arguments, want 3", byCost, byArgs)
	}
	// Two dummy programs of 6 bytes share the free allowance with the stage.
	if SaltedProgramSize+2*6 > 3*1000 {
		t.Fatalf("program %d bytes would pay a surcharge in a group of 3", SaltedProgramSize)
	}
}
