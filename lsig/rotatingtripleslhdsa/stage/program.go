// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stage builds canonical rotating SLH-DSA triple authorizers.
// Every spend requires an SLH-DSA signature under the parameter set the
// binary is built with (rotatingkey.RotatingSlhdsaHeight, see shape.go), Ed25519 and
// Falcon-1024 over its TxID.
package stage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// TEALVersion is the AVM version of every stage program.
	TEALVersion = 13

	// MaxValidityWindow is the largest LastValid - FirstValid the program accepts.
	MaxValidityWindow = 100

	// ConstantSize is the size of the Ed25519 public key.
	ConstantSize = 32

	// FalconPublicKeySize is the embedded Falcon-1024 public key size.
	FalconPublicKeySize = 1793

	// HashSize is the SLH-DSA node/seed size.
	HashSize               = slhdsa.N
	Ed25519SignatureSize   = 64
	FalconSignatureMaxSize = 1423
	// ForsChunkSize is the first SLH-DSA argument, R with the FORS
	// signature, the same for every shape; the hypertree layers follow in
	// the arguments ChunkSizes lists.
	ForsChunkSize = 16 + slhdsa.ForsSignatureSize

	// SaltSearchLimit is the number of salt values the v13 assembler tries.
	SaltSearchLimit = 128

	opIntcblock  = 0x20
	saltTailSize = 3

	// Placeholder fill bytes the template was assembled with.
	fillEd25519 = 0x33
	fillFalcon  = 0x44
	fillSeed    = 0x11
	fillRoot    = 0x22
)

var (
	// ErrNoOffCurveSalt reports that every salt candidate hashed on-curve
	// (probability about 2^-128). The stage is unusable and must be skipped.
	ErrNoOffCurveSalt = errors.New("no off-curve salt for rotating slhdsa stage")

	// ErrInvalidProgram reports bytes that are not a canonical stage program.
	ErrInvalidProgram = errors.New("invalid rotating slhdsa stage program")
)

// PublicKeys are the constants embedded in a stage program.
type PublicKeys struct {
	Ed25519 [ConstantSize]byte
	Falcon  [FalconPublicKeySize]byte
	Root    [HashSize]byte
	Seed    [HashSize]byte
}

// Program is a final, off-curve stage program and its address.
type Program struct {
	Bytecode []byte
	Address  types.Address
	Salted   bool
	Salt     byte
}

// offsets of the constant slots in the template, found once at init.
var (
	ed25519KeyOffset int
	falconKeyOffset  int
	seedOffset       int
	rootOffset       int
)

func init() {
	if len(template) == 0 {
		// Bootstrap only: TestDumpTemplate regenerates the frozen templates
		// from the verifier sources; until then Build refuses every key.
		return
	}
	find := func(fill byte, size int) int {
		run := bytes.Repeat([]byte{fill}, size)
		off := bytes.Index(template, run)
		if off < 0 || bytes.Contains(template[off+1:], run) {
			panic(fmt.Sprintf("rotating slhdsa stage template: placeholder %#x x%d is not unique", fill, size))
		}
		return off
	}
	ed25519KeyOffset = find(fillEd25519, ConstantSize)
	falconKeyOffset = find(fillFalcon, FalconPublicKeySize)
	seedOffset = find(fillSeed, HashSize)
	rootOffset = find(fillRoot, HashSize)
}

// Build assembles the stage program for keys. If the unsalted program's
// address is on-curve, it appends intcblock 1 <salt> with the first salt in
// [0, 128) that yields an off-curve address, exactly as the v13 assembler does.
func Build(keys *PublicKeys) (Program, error) {
	if keys == nil {
		return Program{}, fmt.Errorf("%w: nil public keys", ErrInvalidProgram)
	}
	if len(template) == 0 {
		return Program{}, fmt.Errorf("%w: no frozen template for hypertree height %d", ErrInvalidProgram, Params.H)
	}
	base := make([]byte, UnsaltedProgramSize, SaltedProgramSize)
	copy(base, template)
	copy(base[ed25519KeyOffset:], keys.Ed25519[:])
	copy(base[falconKeyOffset:], keys.Falcon[:])
	copy(base[seedOffset:], keys.Seed[:])
	copy(base[rootOffset:], keys.Root[:])

	addr, err := Address(base)
	if err != nil {
		return Program{}, err
	}
	if !lsigsalt.IsOnCurve(addr) {
		return Program{Bytecode: base, Address: addr}, nil
	}

	candidate := append(base, opIntcblock, 0x01, 0x00)
	for salt := range SaltSearchLimit {
		candidate[UnsaltedProgramSize+2] = byte(salt)
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

// Parse is the strict inverse of Build. It accepts only bytes Build would
// produce for the embedded constants: the fixed template, and a salt tail
// present exactly when the unsalted address is on-curve and holding the
// first off-curve salt.
func Parse(bytecode []byte) (*PublicKeys, Program, error) {
	if len(bytecode) != UnsaltedProgramSize && len(bytecode) != SaltedProgramSize {
		return nil, Program{}, fmt.Errorf("%w: length %d", ErrInvalidProgram, len(bytecode))
	}
	keys := &PublicKeys{}
	copy(keys.Ed25519[:], bytecode[ed25519KeyOffset:ed25519KeyOffset+ConstantSize])
	copy(keys.Falcon[:], bytecode[falconKeyOffset:falconKeyOffset+FalconPublicKeySize])
	copy(keys.Seed[:], bytecode[seedOffset:seedOffset+HashSize])
	copy(keys.Root[:], bytecode[rootOffset:rootOffset+HashSize])

	want, err := Build(keys)
	if err != nil {
		return nil, Program{}, err
	}
	if !bytes.Equal(bytecode, want.Bytecode) {
		return nil, Program{}, fmt.Errorf("%w: template or salt mismatch", ErrInvalidProgram)
	}
	return keys, want, nil
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

// TEALSource returns the source used to assemble the selected shape's
// frozen template.
func TEALSource(keys *PublicKeys) string {
	return substitute(selected.teal, keys)
}

func substitute(teal string, keys *PublicKeys) string {
	return strings.NewReplacer("@ED25519@", hex.EncodeToString(keys.Ed25519[:]),
		"@FALCON@", hex.EncodeToString(keys.Falcon[:]), "@SEED@", hex.EncodeToString(keys.Seed[:]),
		"@ROOT@", hex.EncodeToString(keys.Root[:])).Replace(teal)
}
