// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/rotatingkey"

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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.HealthCheck().Do(ctx); err != nil {
		t.Skipf("algod unreachable: %v", err)
	}
	for _, salted := range []bool{false, true} {
		keys, want := keysWithSalt(t, salted)
		result, err := client.TealCompile([]byte(TEALSource(keys))).Do(ctx)
		if err != nil {
			t.Fatalf("TealCompile() error = %v", err)
		}
		got, err := base64.StdEncoding.DecodeString(result.Result)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytecode) {
			t.Fatalf("salted=%v: local bytecode differs from algod\nlocal: %x\nalgod: %x", salted, want.Bytecode, got)
		}
		if result.Hash != want.Address.String() {
			t.Fatalf("algod hash %s, local address %s", result.Hash, want.Address)
		}
	}
}

// TestSizesMatchPrimitive pins the argument layout to the parameter set the
// stage signs under, and the frozen sizes and cost ceiling to the selected
// hypertree height.
func TestSizesMatchPrimitive(t *testing.T) {
	if int(Params.H) != rotatingkey.RotatingSlhdsaHeight {
		t.Fatalf("parameter set %s does not match rotatingkey.RotatingSlhdsaHeight %d", Params, rotatingkey.RotatingSlhdsaHeight)
	}
	total := 0
	for i, c := range ChunkSizes {
		if c > 4096 {
			t.Fatalf("argument %d is %d bytes, above the AVM value limit", i, c)
		}
		total += c
	}
	if ChunkSizes[0] != ForsChunkSize || total != Params.SignatureSize || SLHSignatureSize != Params.SignatureSize {
		t.Fatalf("chunks %v, signature %d", ChunkSizes, Params.SignatureSize)
	}
	if MaxAcceptedSteps != int(Params.D)*MaxStepsPerLayer {
		t.Fatalf("accepted steps %d for %d layers", MaxAcceptedSteps, Params.D)
	}
}

// frozen pins the per-height literals that other packages and documents
// restate: program sizes, argument bytes, the opcode ceiling and the group
// it needs.
var frozen = map[int]struct {
	unsalted, salted, args, cost, group int
}{
	20: {2834, 2837, 5855, 68465, 6},
	63: {2863, 2866, 9343, 187258, 10},
}

func TestResourceCeiling(t *testing.T) {
	want, ok := frozen[rotatingkey.RotatingSlhdsaHeight]
	if !ok {
		t.Fatalf("no frozen expectations for height %d", rotatingkey.RotatingSlhdsaHeight)
	}
	if UnsaltedProgramSize != want.unsalted || SaltedProgramSize != want.salted || MaxArgumentBytes != want.args {
		t.Fatalf("frozen sizes changed: program %d/%d, arguments %d", UnsaltedProgramSize, SaltedProgramSize, MaxArgumentBytes)
	}
	maximum := 0
	for c := 0; c <= 32*15; c++ {
		steps := c + 45 - ((c >> 8) & 15) - ((c >> 4) & 15) - (c & 15)
		if steps > maximum {
			maximum = steps
		}
	}
	if maximum != MaxStepsPerLayer {
		t.Fatalf("chain bound %d", maximum)
	}
	if MaxOpcodeCost != want.cost {
		t.Fatalf("opcode ceiling %d, want %d", MaxOpcodeCost, want.cost)
	}
	byCost := (MaxOpcodeCost + 19999) / 20000
	byArgs := (MaxArgumentBytes + 999) / 1000
	if max(byCost, byArgs) != want.group {
		t.Fatalf("group of %d by cost, %d by arguments, want %d", byCost, byArgs, want.group)
	}
	if _, err := Build(nil); !errors.Is(err, ErrInvalidProgram) {
		t.Fatal("nil keys accepted")
	}
}
