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
	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func randomKeys(t *testing.T) *PublicKeys {
	t.Helper()
	keys := &PublicKeys{}
	for _, b := range [][]byte{keys.Ed25519[:], keys.Falcon[:], keys.Tweak[:], keys.Wots[:]} {
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

// The triple stage needs a four-transaction group: its arguments exceed
// three pooled LogicSig size units, while its opcode cost and program fit
// within that group.
func TestProgramSizesAndCost(t *testing.T) {
	if UnsaltedProgramSize != 2093 || SaltedProgramSize != 2096 {
		t.Fatalf("program sizes %d/%d", UnsaltedProgramSize, SaltedProgramSize)
	}
	if MaxArgumentBytes != 3631 {
		t.Fatalf("argument bytes %d", MaxArgumentBytes)
	}
	if MaxArgumentBytes <= 3000 || MaxArgumentBytes > 4000 {
		t.Fatalf("argument bytes %d no longer need exactly four pooled transactions", MaxArgumentBytes)
	}
	if MaxOpcodeCost != 59_767 || MaxOpcodeCost >= 60_000 {
		t.Fatalf("worst case %d", MaxOpcodeCost)
	}
	if got := OpcodeCost(wots.MaxVerifySteps) + 1; got != MaxOpcodeCost {
		t.Fatalf("MaxOpcodeCost %d != %d", MaxOpcodeCost, got)
	}
	if SaltedProgramSize > 4000 {
		t.Fatalf("program %d exceeds the free program bytes of a four-transaction group", SaltedProgramSize)
	}
	// The four constant slots hold the placeholders the template was
	// assembled with, each preceded by its pushbytes length.
	for _, slot := range []struct {
		off, size int
		fill      byte
		prefix    []byte
	}{
		{ed25519KeyOffset, ConstantSize, 0x33, []byte{0x80, ConstantSize}},
		{falconKeyOffset, FalconPublicKeySize, 0x44, []byte{0x80, 0x81, 0x0e}},
		{tweakOffset, ConstantSize, 0x11, []byte{0x80, ConstantSize}},
		{wotsKeyOffset, ConstantSize, 0x22, []byte{0x80, ConstantSize}},
	} {
		if !bytes.Equal(template[slot.off:slot.off+slot.size], bytes.Repeat([]byte{slot.fill}, slot.size)) {
			t.Fatalf("template slot at %d does not hold placeholder %#x", slot.off, slot.fill)
		}
		if !bytes.Equal(template[slot.off-len(slot.prefix):slot.off], slot.prefix) {
			t.Fatalf("slot at %d is not preceded by its pushbytes length", slot.off)
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
	for _, off := range []int{10, falconKeyOffset - 1, tweakOffset - 3, UnsaltedProgramSize - 1} {
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
// requires byte equality with Build, for both unsalted and salted programs.
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
