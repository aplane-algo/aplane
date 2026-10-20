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
	"github.com/aplane-algo/aplane/internal/crypto/xmss"
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
	var stage [8]byte
	if _, err := rand.Read(stage[:]); err != nil {
		t.Fatal(err)
	}
	_, keys.Lo, keys.Hi = RangeFor(uint64(stage[0]) | uint64(stage[1])<<8)
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

// The XMSS stage needs an eight-transaction group: its worst accepting path
// costs more than seven pooled opcode units, while its program and
// arguments fit in seven size units.
func TestProgramSizesAndCost(t *testing.T) {
	if UnsaltedProgramSize != 2654 || SaltedProgramSize != 2657 {
		t.Fatalf("program sizes %d/%d", UnsaltedProgramSize, SaltedProgramSize)
	}
	if MaxArgumentBytes != 4179 {
		t.Fatalf("argument bytes %d", MaxArgumentBytes)
	}
	if MaxOpcodeCost <= 140_000 || MaxOpcodeCost > 160_000 {
		t.Fatalf("worst case %d no longer needs exactly eight pooled transactions", MaxOpcodeCost)
	}
	if got := OpcodeCost(xmss.MaxVerifySteps); got != MaxOpcodeCost {
		t.Fatalf("MaxOpcodeCost %d != %d", MaxOpcodeCost, got)
	}
	if uint64(SaltedProgramSize)+MaxArgumentBytes > 8000 {
		t.Fatalf("program and arguments %d exceed the free bytes of an eight-transaction group", SaltedProgramSize+MaxArgumentBytes)
	}
	// The constant slots hold the placeholders the template was assembled
	// with, each preceded by its pushbytes length (the seed sits inside the
	// 64-byte toByte(3) || SEED constant).
	for _, slot := range []struct {
		off, size int
		fill      byte
		prefix    []byte
	}{
		{ed25519KeyOffset, ConstantSize, fillEd25519, []byte{0x80, ConstantSize}},
		{falconKeyOffset, FalconPublicKeySize, fillFalcon, []byte{0x80, 0x81, 0x0e}},
		{rootOffset, ConstantSize, fillRoot, []byte{0x80, ConstantSize}},
		{loOffset, RangeBoundSize, fillLo, []byte{0x80, RangeBoundSize}},
		{hiOffset, RangeBoundSize, fillHi, []byte{0x80, RangeBoundSize}},
		{seedOffset, ConstantSize, fillSeed, append(append([]byte{0x80, 2 * ConstantSize}, make([]byte, ConstantSize-1)...), 0x03)},
	} {
		if !bytes.Equal(template[slot.off:slot.off+slot.size], bytes.Repeat([]byte{slot.fill}, slot.size)) {
			t.Fatalf("template slot at %d does not hold placeholder %#x", slot.off, slot.fill)
		}
		if !bytes.Equal(template[slot.off-len(slot.prefix):slot.off], slot.prefix) {
			t.Fatalf("slot at %d is not preceded by its pushbytes prefix", slot.off)
		}
	}
}

func TestRangeFor(t *testing.T) {
	if StagesPerTree != 1024 || IndicesPerStage != 64 {
		t.Fatalf("StagesPerTree %d IndicesPerStage %d", StagesPerTree, IndicesPerStage)
	}
	for _, tc := range []struct{ stage, tree, lo, hi uint64 }{
		{0, 0, 0, 64}, {1, 0, 64, 128}, {1023, 0, 65472, 65536}, {1024, 1, 0, 64}, {2047, 1, 65472, 65536}, {2048, 2, 0, 64},
	} {
		tree, lo, hi := RangeFor(tc.stage)
		if tree != tc.tree || lo != tc.lo || hi != tc.hi {
			t.Fatalf("RangeFor(%d) = %d, %d, %d; want %d, %d, %d", tc.stage, tree, lo, hi, tc.tree, tc.lo, tc.hi)
		}
	}
}

func TestBuildRejectsBadRange(t *testing.T) {
	keys := randomKeys(t)
	for _, r := range [][2]uint64{{64, 64}, {65, 64}, {65536, 65600}, {65500, 65537}} {
		keys.Lo, keys.Hi = r[0], r[1]
		if _, err := Build(keys); !errors.Is(err, ErrInvalidProgram) {
			t.Fatalf("range %v: err = %v", r, err)
		}
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
	for _, off := range []int{10, falconKeyOffset - 1, seedOffset - 3, loOffset - 2, UnsaltedProgramSize - 1} {
		tampered := bytes.Clone(unsalted.Bytecode)
		tampered[off] ^= 1
		if _, _, err := Parse(tampered); !errors.Is(err, ErrInvalidProgram) {
			t.Fatalf("template tampered at %d accepted: %v", off, err)
		}
	}
	// A range the program would never embed parses as invalid too.
	badRange := bytes.Clone(unsalted.Bytecode)
	copy(badRange[hiOffset:], []byte{0, 0, 0, 0, 0, 1, 0, 1})
	if _, _, err := Parse(badRange); !errors.Is(err, ErrInvalidProgram) {
		t.Fatalf("out-of-range bounds accepted: %v", err)
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
