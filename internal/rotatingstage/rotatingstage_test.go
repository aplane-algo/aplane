// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingstage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

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
