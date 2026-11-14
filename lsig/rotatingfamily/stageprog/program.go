// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stageprog finishes and validates frozen rotating stage programs,
// and owns the stage prefix every one of them opens with. It is client-safe:
// templates and public-key layouts belong to each scheme, and no private-key
// operations or signer registration are linked here.
package stageprog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// SaltSearchLimit is the number of salt values the v13 assembler tries.
	SaltSearchLimit = 128
	// SaltTailSize is the size of the trailing intcblock 1 <salt> encoding.
	SaltTailSize = 3

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

	opIntcblock = 0x20
	opVersion13 = 0x0d
	opPushbytes = 0x80
	opPop       = 0x48
)

var (
	// ErrNoOffCurveSalt reports that every salt candidate hashed on-curve.
	// The stage is unusable and must be skipped.
	ErrNoOffCurveSalt = errors.New("no off-curve salt for rotating stage")
	// ErrInvalidProgram reports bytes that are not a canonical stage program.
	ErrInvalidProgram = errors.New("invalid rotating stage program")
)

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

// Program is a final, off-curve stage program and its address.
type Program struct {
	Bytecode []byte
	Address  types.Address
	Salted   bool
	Salt     byte
}

// Finish applies the frozen TEAL v13 assembler salt rule to a filled template.
// An off-curve program is returned unchanged; otherwise the first salt in
// [0, 128) yielding an off-curve address is appended as intcblock 1 <salt>.
// The caller transfers ownership of unsalted, including its spare capacity;
// the returned Bytecode may share that backing array.
func Finish(unsalted []byte) (Program, error) {
	addr, err := Address(unsalted)
	if err != nil {
		return Program{}, err
	}
	if !lsigsalt.IsOnCurve(addr) {
		return Program{Bytecode: unsalted, Address: addr}, nil
	}

	candidate := append(unsalted, opIntcblock, 0x01, 0x00)
	for salt := range SaltSearchLimit {
		candidate[len(unsalted)+2] = byte(salt)
		addr, err := Address(candidate)
		if err != nil {
			return Program{}, err
		}
		if !lsigsalt.IsOnCurve(addr) {
			return Program{Bytecode: candidate, Address: addr, Salted: true, Salt: byte(salt)}, nil
		}
	}
	return Program{}, ErrNoOffCurveSalt
}

// ParseStrict checks length before asking rebuild to extract the scheme's
// public keys and build their canonical program. It accepts only byte-for-byte
// equality with that rebuilt program, including the first off-curve salt.
// unsaltedSize is the scheme's frozen template size. rebuild must not mutate
// bytecode; it must produce independently built bytes, not echo the input.
func ParseStrict(bytecode []byte, unsaltedSize int, rebuild func([]byte) (Program, error)) (Program, error) {
	if len(bytecode) != unsaltedSize && len(bytecode) != unsaltedSize+SaltTailSize {
		return Program{}, fmt.Errorf("%w: length %d", ErrInvalidProgram, len(bytecode))
	}
	want, err := rebuild(bytecode)
	if err != nil {
		return Program{}, err
	}
	if !bytes.Equal(bytecode, want.Bytecode) {
		return Program{}, fmt.Errorf("%w: template or salt mismatch", ErrInvalidProgram)
	}
	return want, nil
}

// Address returns the LogicSig address of bytecode:
// SHA-512/256("Program" || bytecode).
func Address(bytecode []byte) (types.Address, error) {
	lsig := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	addr, err := lsig.Address()
	if err != nil {
		return types.Address{}, fmt.Errorf("derive stage address: %w", err)
	}
	return addr, nil
}
