// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stageprog

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

// programWithAddress returns the first 40-byte program, counting up from
// start, whose address is on-curve or off-curve as wanted.
func programWithAddress(t *testing.T, start uint64, onCurve bool) []byte {
	t.Helper()
	for n := start; n < start+1000; n++ {
		code := make([]byte, 40, 40+SaltTailSize)
		code[0] = 0x0d
		binary.BigEndian.PutUint64(code[8:], n)
		addr, err := Address(code)
		if err != nil {
			t.Fatal(err)
		}
		if lsigsalt.IsOnCurve(addr) == onCurve {
			return code
		}
	}
	t.Fatalf("no program with on-curve %v near %d", onCurve, start)
	return nil
}

// TestFinishFollowsTheAssemblerSaltRule checks the salt rule directly: an
// off-curve program is returned as it is, and an on-curve one gets the
// intcblock 1 <salt> tail with the first salt whose address is off-curve.
func TestFinishFollowsTheAssemblerSaltRule(t *testing.T) {
	plain := programWithAddress(t, 0, false)
	got, err := Finish(bytes.Clone(plain))
	if err != nil {
		t.Fatal(err)
	}
	wantAddr, err := Address(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.Salted || !bytes.Equal(got.Bytecode, plain) || got.Address != wantAddr {
		t.Fatalf("off-curve program came back salted %v, %d bytes", got.Salted, len(got.Bytecode))
	}

	onCurve := programWithAddress(t, 0, true)
	got, err = Finish(bytes.Clone(onCurve))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Salted || len(got.Bytecode) != len(onCurve)+SaltTailSize {
		t.Fatalf("on-curve program came back salted %v, %d bytes", got.Salted, len(got.Bytecode))
	}
	for salt := range int(got.Salt) + 1 {
		candidate := append(bytes.Clone(onCurve), opIntcblock, 0x01, byte(salt))
		addr, err := Address(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if off := !lsigsalt.IsOnCurve(addr); off != (salt == int(got.Salt)) {
			t.Fatalf("salt %d off-curve %v, but Finish chose salt %d", salt, off, got.Salt)
		}
		if salt == int(got.Salt) && (!bytes.Equal(candidate, got.Bytecode) || addr != got.Address) {
			t.Fatal("Finish's program or address differs from the chosen salt's")
		}
	}
}

func TestParseStrictChecksLengthBeforeExtraction(t *testing.T) {
	const unsaltedSize = 10
	for _, size := range []int{0, 1, unsaltedSize - 1, unsaltedSize + 1, unsaltedSize + 2, unsaltedSize + 4} {
		program, err := ParseStrict(make([]byte, size), unsaltedSize, func([]byte) (Program, error) {
			t.Fatal("extraction called with an invalid length")
			return Program{}, nil
		})
		if !errors.Is(err, ErrInvalidProgram) || program.Bytecode != nil {
			t.Fatalf("length %d: got %+v, %v", size, program, err)
		}
	}
}

func TestParseStrictPropagatesBuildFailure(t *testing.T) {
	want := errors.New("scheme refused embedded constants")
	program, err := ParseStrict(make([]byte, 10), 10, func([]byte) (Program, error) {
		return Program{}, want
	})
	if !errors.Is(err, want) || program.Bytecode != nil {
		t.Fatalf("got %+v, %v", program, err)
	}
}

func TestParseStrictReturnsRebuiltProgram(t *testing.T) {
	for _, salted := range []bool{false, true} {
		const unsaltedSize = 10
		size := unsaltedSize
		if salted {
			size += SaltTailSize
		}
		input := make([]byte, size)
		rebuilt := Program{Bytecode: bytes.Clone(input), Salted: salted, Salt: 2}
		rebuilt.Address[0] = 42
		program, err := ParseStrict(input, unsaltedSize, func(code []byte) (Program, error) {
			if !bytes.Equal(code, input) {
				t.Fatal("extraction received different bytes")
			}
			return rebuilt, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if program.Address != rebuilt.Address || program.Salted != salted || program.Salt != rebuilt.Salt {
			t.Fatalf("rebuilt metadata lost: %+v", program)
		}
		input[0] = 1
		if program.Bytecode[0] != 0 {
			t.Fatal("returned caller's input instead of independently rebuilt bytes")
		}
		if _, err := ParseStrict(input, unsaltedSize, func([]byte) (Program, error) {
			return rebuilt, nil
		}); !errors.Is(err, ErrInvalidProgram) {
			t.Fatalf("accepted bytes differing from the canonical program: %v", err)
		}
	}
}

// TestStagePrefix writes stage numbers into a prefix and reads them back, and
// checks that the TEAL literal is the eight big-endian bytes the slot holds.
func TestStagePrefix(t *testing.T) {
	for _, stage := range []uint64{0, 1, 418, 1 << 40, math.MaxUint64} {
		program := []byte{0x0d, 0x80, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x31, 0x20}
		PutStage(program, stage)
		got, err := ReadStage(program)
		if err != nil || got != stage {
			t.Fatalf("stage %d read back as %d, %v", stage, got, err)
		}
		if StageHex(stage) != hex.EncodeToString(program[StageOffset:StageOffset+StageSize]) {
			t.Fatalf("stage %d: literal %s, slot % x", stage, StageHex(stage), program[StageOffset:StageOffset+StageSize])
		}
	}
	if PrefixSize != 12 || StageOffset != 3 || StageSize != 8 {
		t.Fatalf("prefix layout %d/%d/%d", StageOffset, StageSize, PrefixSize)
	}
}

// TestReadStageRefusesAProgramWithoutThePrefix changes each opcode byte of
// the prefix and cuts it short.
func TestReadStageRefusesAProgramWithoutThePrefix(t *testing.T) {
	prefix := []byte{0x0d, 0x80, 0x08, 0, 0, 0, 0, 0, 0, 0x01, 0xa2, 0x48}
	if got, err := ReadStage(prefix); err != nil || got != 418 {
		t.Fatalf("prefix read as %d, %v", got, err)
	}
	for _, off := range []int{0, 1, 2, PrefixSize - 1} {
		bad := bytes.Clone(prefix)
		bad[off] ^= 1
		if _, err := ReadStage(bad); !errors.Is(err, ErrInvalidProgram) {
			t.Errorf("prefix changed at %d accepted: %v", off, err)
		}
	}
	for n := range PrefixSize {
		if _, err := ReadStage(prefix[:n]); !errors.Is(err, ErrInvalidProgram) {
			t.Errorf("%d-byte program accepted: %v", n, err)
		}
	}
	// A program that opens with the guard, as stage programs did before the
	// stage number, has no prefix.
	if _, err := ReadStage([]byte{0x0d, 0x31, 0x20, 0x32, 0x03, 0x13, 0x44, 0x31, 0x20, 0x31, 0x00, 0x13, 0x44}); !errors.Is(err, ErrInvalidProgram) {
		t.Errorf("a program without the stage number accepted: %v", err)
	}
}
