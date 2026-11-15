// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatingstage owns the stage prefix every rotating stage program
// opens with, for every rotating key type. It imports only the standard
// library, so the stage packages under lsig/, the signer's chain reads and
// clients can all use it. It reads the prefix only: whether bytes are a stage
// program of a given key type is that type's strict stage.Parse to decide.
package rotatingstage

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// StageOffset is where every stage program holds its stage number, and
	// StageSize is the number's width: eight bytes, big-endian. Every stage
	// program of every rotating key type opens with the same prefix,
	// PrefixSize bytes long:
	//
	//	#pragma version 13      0d
	//	pushbytes 0x<stage>     80 08 <stage>
	//	pop                     48
	//
	// The program never reads the number. It is there so the hashed program,
	// and with it the stage's address, names its stage, and so a spend's
	// program shows which stage signed it. The width is fixed so every
	// template keeps one size.
	StageOffset = 3
	StageSize   = 8
	PrefixSize  = StageOffset + StageSize + 1

	opVersion13 = 0x0d
	opPushbytes = 0x80
	opPop       = 0x48
)

// ErrInvalidProgram reports bytes that are not a canonical stage program,
// a program without the stage prefix among them. The stage packages' strict
// Parse reports the same error.
var ErrInvalidProgram = errors.New("invalid rotating stage program")

// StageHex is the stage number as the hexadecimal digits of the prefix's
// pushbytes literal, for a template's TEAL source.
func StageHex(stage uint64) string {
	return fmt.Sprintf("%016x", stage)
}

// PutStage writes stage into the stage slot of a filled template.
func PutStage(program []byte, stage uint64) {
	binary.BigEndian.PutUint64(program[StageOffset:StageOffset+StageSize], stage)
}

// ReadStage returns the stage number a stage program's prefix holds. It
// checks the prefix only. Whether the program is a stage program of a given
// key type, and so whether the number means anything, is that key type's
// strict Parse to decide.
func ReadStage(program []byte) (uint64, error) {
	if len(program) < PrefixSize || program[0] != opVersion13 || program[1] != opPushbytes ||
		program[2] != StageSize || program[PrefixSize-1] != opPop {
		return 0, fmt.Errorf("%w: no stage prefix", ErrInvalidProgram)
	}
	return binary.BigEndian.Uint64(program[StageOffset:]), nil
}
