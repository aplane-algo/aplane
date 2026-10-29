// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stageprog

import (
	"bytes"
	"encoding/binary"
	"errors"
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
