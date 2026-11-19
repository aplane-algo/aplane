// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stage builds canonical rotating WOTS+C triple authorizers. Every
// spend requires a signature from a tree of 64 WOTS+C keys, Ed25519 and
// Falcon-1024 over its TxID.
package stage

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/internal/falconparams"
	"github.com/aplane-algo/aplane/internal/rotatingstage"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stageprog"
)

const (
	// MaxValidityWindow is the largest LastValid - FirstValid the program accepts.
	MaxValidityWindow = 100

	// ConstantSize is the size of the Ed25519 public key.
	ConstantSize = 32

	// FalconPublicKeySize is the embedded Falcon-1024 public key size.
	FalconPublicKeySize = falconparams.PublicKeySize

	// HashSize is the WOTS+C seed and root size.
	HashSize               = wotsc.N
	Ed25519SignatureSize   = 64
	FalconSignatureMaxSize = falconparams.CompressedSignatureMaxSize

	// MaxArgumentBytes bounds every spend's LogicSig arguments.
	MaxArgumentBytes = wotsc.SignatureSize + Ed25519SignatureSize + FalconSignatureMaxSize

	opIntcblock  = 0x20
	saltTailSize = stageprog.SaltTailSize

	// Placeholder fill bytes the template was assembled with.
	fillEd25519 = 0x33
	fillFalcon  = 0x44
	fillSeed    = 0x11
	fillRoot    = 0x22
	fillStage   = 0x77
)

var (
	// ErrInvalidProgram reports bytes that are not a canonical stage program.
	ErrInvalidProgram = stageprog.ErrInvalidProgram
)

// PublicKeys are the constants embedded in a stage program.
type PublicKeys struct {
	// Stage is the stage number, the program's first constant. The program
	// never reads it.
	Stage   uint64
	Ed25519 [ConstantSize]byte
	Falcon  [FalconPublicKeySize]byte
	Root    [HashSize]byte
	Seed    [HashSize]byte
}

// Program is a final, off-curve stage program and its address.
type Program = stageprog.Program

//go:embed verifier.teal
var verifierSource string

// UnsaltedProgramSize is the frozen template's size and SaltedProgramSize adds
// the three-byte intcblock tail.
var (
	UnsaltedProgramSize = len(template)
	SaltedProgramSize   = UnsaltedProgramSize + saltTailSize
)

// offsets of the constant slots in the template, found once at init.
var (
	ed25519KeyOffset int
	falconKeyOffset  int
	seedOffset       int
	rootOffset       int
)

func init() {
	find := func(fill byte, size int) int {
		run := bytes.Repeat([]byte{fill}, size)
		off := bytes.Index(template, run)
		if off < 0 || bytes.Contains(template[off+1:], run) {
			panic(fmt.Sprintf("rotating wotsc stage template: placeholder %#x x%d is not unique", fill, size))
		}
		return off
	}
	ed25519KeyOffset = find(fillEd25519, ConstantSize)
	falconKeyOffset = find(fillFalcon, FalconPublicKeySize)
	seedOffset = find(fillSeed, HashSize)
	rootOffset = find(fillRoot, HashSize)
	if find(fillStage, rotatingstage.StageSize) != rotatingstage.StageOffset {
		panic("rotating wotsc stage template: the stage constant is not at the stage prefix's offset")
	}
	if _, err := rotatingstage.ReadStage(template); err != nil {
		panic(fmt.Sprintf("rotating wotsc stage template: %v", err))
	}
}

// Build assembles the stage program for keys. If the unsalted program's
// address is on-curve, it appends intcblock 1 <salt> with the first salt in
// [0, 128) that yields an off-curve address, exactly as the v13 assembler does.
func Build(keys *PublicKeys) (Program, error) {
	if keys == nil {
		return Program{}, fmt.Errorf("%w: nil public keys", ErrInvalidProgram)
	}
	base := make([]byte, UnsaltedProgramSize, SaltedProgramSize)
	copy(base, template)
	rotatingstage.PutStage(base, keys.Stage)
	copy(base[ed25519KeyOffset:], keys.Ed25519[:])
	copy(base[falconKeyOffset:], keys.Falcon[:])
	copy(base[seedOffset:], keys.Seed[:])
	copy(base[rootOffset:], keys.Root[:])

	return stageprog.Finish(base)
}

// Parse is the strict inverse of Build. It accepts only bytes Build would
// produce for the embedded constants: the fixed template, and a salt tail
// present exactly when the unsalted address is on-curve and holding the
// first off-curve salt.
func Parse(bytecode []byte) (*PublicKeys, Program, error) {
	keys := &PublicKeys{}
	program, err := stageprog.ParseStrict(bytecode, UnsaltedProgramSize, func(code []byte) (Program, error) {
		var err error
		if keys.Stage, err = rotatingstage.ReadStage(code); err != nil {
			return Program{}, err
		}
		copy(keys.Ed25519[:], code[ed25519KeyOffset:ed25519KeyOffset+ConstantSize])
		copy(keys.Falcon[:], code[falconKeyOffset:falconKeyOffset+FalconPublicKeySize])
		copy(keys.Seed[:], code[seedOffset:seedOffset+HashSize])
		copy(keys.Root[:], code[rootOffset:rootOffset+HashSize])
		return Build(keys)
	})
	if err != nil {
		return nil, Program{}, err
	}
	return keys, program, nil
}

// TEALSource returns the source used to assemble the frozen template, with
// keys substituted.
func TEALSource(keys *PublicKeys) string {
	return strings.NewReplacer("@STAGE@", rotatingstage.StageHex(keys.Stage),
		"@ED25519@", hex.EncodeToString(keys.Ed25519[:]),
		"@FALCON@", hex.EncodeToString(keys.Falcon[:]), "@SEED@", hex.EncodeToString(keys.Seed[:]),
		"@ROOT@", hex.EncodeToString(keys.Root[:])).Replace(verifierSource)
}
