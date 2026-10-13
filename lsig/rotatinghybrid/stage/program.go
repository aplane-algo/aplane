// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stage builds and parses the per-stage LogicSig program of the
// aplane.rotating-hybrid.v1 key type.
//
// Every stage runs the same TEAL v13 program; only the embedded Falcon-1024
// and Ed25519 public keys differ:
//
//	#pragma version 13
//	txn TxID; arg 0; pushbytes <falcon_pk>;  falcon_verify;      assert
//	txn TxID; arg 1; pushbytes <ed25519_pk>; ed25519verify_bare; assert
//	txn RekeyTo; global ZeroAddress; !=; assert
//	txn RekeyTo; txn Sender; !=; assert
//	txn CloseRemainderTo; global ZeroAddress; ==; assert
//	txn LastValid; txn FirstValid; -; pushint 100; <=; assert
//	pushint 1
//
// Bytecode is assembled locally by copying the two keys into a frozen byte
// template, then salted off-curve with the same trailing-intcblock rule the
// v13 assembler applies, so that stages can be derived offline and in bulk
// without trusting a node for addresses. The assembler cross-check test pins
// this package to stock algod output.
//
// This package is client-safe: it holds no private keys and does not link the
// CGo Falcon implementation.
package stage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/falconparams"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// TEALVersion is the AVM version of every stage program.
	TEALVersion = 13

	// MaxValidityWindow is the largest LastValid - FirstValid the program accepts.
	MaxValidityWindow = 100

	// FalconPublicKeySize and Ed25519PublicKeySize are the embedded key sizes.
	FalconPublicKeySize  = falconparams.PublicKeySize
	Ed25519PublicKeySize = 32

	// FalconSignatureMaxSize and Ed25519SignatureSize bound arguments 0 and 1.
	FalconSignatureMaxSize = falconparams.CompressedSignatureMaxSize
	Ed25519SignatureSize   = 64

	// MaxArgumentBytes is the worst-case total of both signature arguments.
	MaxArgumentBytes = FalconSignatureMaxSize + Ed25519SignatureSize

	// UnsaltedProgramSize and SaltedProgramSize are the only two program sizes.
	UnsaltedProgramSize = len(templatePrefix) + FalconPublicKeySize + len(templateMiddle) +
		Ed25519PublicKeySize + len(templateSuffix)
	SaltedProgramSize = UnsaltedProgramSize + saltTailSize

	// OpcodeCost is the cost of every accepting path: 27 single-cost opcodes,
	// falcon_verify (1,700) and ed25519verify_bare (1,900). A salted program
	// adds one for the trailing intcblock.
	OpcodeCost       = 27 + 1700 + 1900
	SaltedOpcodeCost = OpcodeCost + 1

	// SaltSearchLimit is the number of salt values the v13 assembler tries.
	SaltSearchLimit = 128

	opIntcblock  = 0x20
	saltTailSize = 3
)

var (
	// version 13; txn TxID; arg 0; pushbytes varuint(1793)
	templatePrefix = [...]byte{0x0d, 0x31, 0x17, 0x2d, 0x80, 0x81, 0x0e}

	// falcon_verify; assert; txn TxID; arg 1; pushbytes varuint(32)
	templateMiddle = [...]byte{0x85, 0x44, 0x31, 0x17, 0x2e, 0x80, 0x20}

	// ed25519verify_bare; assert
	// txn RekeyTo; global ZeroAddress; !=; assert
	// txn RekeyTo; txn Sender; !=; assert
	// txn CloseRemainderTo; global ZeroAddress; ==; assert
	// txn LastValid; txn FirstValid; -; pushint 100; <=; assert
	// pushint 1
	templateSuffix = [...]byte{
		0x84, 0x44,
		0x31, 0x20, 0x32, 0x03, 0x13, 0x44,
		0x31, 0x20, 0x31, 0x00, 0x13, 0x44,
		0x31, 0x09, 0x32, 0x03, 0x12, 0x44,
		0x31, 0x04, 0x31, 0x02, 0x09, 0x81, MaxValidityWindow, 0x0e, 0x44,
		0x81, 0x01,
	}

	falconKeyOffset  = len(templatePrefix)
	middleOffset     = falconKeyOffset + FalconPublicKeySize
	ed25519KeyOffset = middleOffset + len(templateMiddle)
	suffixOffset     = ed25519KeyOffset + Ed25519PublicKeySize
)

var (
	// ErrNoOffCurveSalt reports that every salt candidate hashed on-curve
	// (probability about 2^-128). The stage is unusable and must be skipped.
	ErrNoOffCurveSalt = errors.New("no off-curve salt for rotating hybrid stage")

	// ErrInvalidProgram reports bytes that are not a canonical stage program.
	ErrInvalidProgram = errors.New("invalid rotating hybrid stage program")
)

// PublicKeys are the two public keys embedded in a stage program.
type PublicKeys struct {
	Falcon  [FalconPublicKeySize]byte
	Ed25519 [Ed25519PublicKeySize]byte
}

// Program is a final, off-curve stage program and its address.
type Program struct {
	Bytecode []byte
	Address  types.Address
	Salted   bool
	Salt     byte
}

// Build assembles the stage program for keys. If the unsalted program's
// address is on-curve, it appends intcblock 1 <salt> with the first salt in
// [0, 128) that yields an off-curve address, exactly as the v13 assembler does.
func Build(keys PublicKeys) (Program, error) {
	base := make([]byte, UnsaltedProgramSize, SaltedProgramSize)
	copy(base, templatePrefix[:])
	copy(base[falconKeyOffset:], keys.Falcon[:])
	copy(base[middleOffset:], templateMiddle[:])
	copy(base[ed25519KeyOffset:], keys.Ed25519[:])
	copy(base[suffixOffset:], templateSuffix[:])

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
// produce for the embedded keys: the fixed template, and a salt tail present
// exactly when the unsalted address is on-curve and holding the first
// off-curve salt.
func Parse(bytecode []byte) (PublicKeys, Program, error) {
	if len(bytecode) != UnsaltedProgramSize && len(bytecode) != SaltedProgramSize {
		return PublicKeys{}, Program{}, fmt.Errorf("%w: length %d", ErrInvalidProgram, len(bytecode))
	}
	if !bytes.Equal(bytecode[:falconKeyOffset], templatePrefix[:]) ||
		!bytes.Equal(bytecode[middleOffset:ed25519KeyOffset], templateMiddle[:]) ||
		!bytes.Equal(bytecode[suffixOffset:UnsaltedProgramSize], templateSuffix[:]) {
		return PublicKeys{}, Program{}, fmt.Errorf("%w: template mismatch", ErrInvalidProgram)
	}

	var keys PublicKeys
	copy(keys.Falcon[:], bytecode[falconKeyOffset:middleOffset])
	copy(keys.Ed25519[:], bytecode[ed25519KeyOffset:suffixOffset])

	want, err := Build(keys)
	if err != nil {
		return PublicKeys{}, Program{}, err
	}
	if !bytes.Equal(bytecode, want.Bytecode) {
		return PublicKeys{}, Program{}, fmt.Errorf("%w: non-canonical salt", ErrInvalidProgram)
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
