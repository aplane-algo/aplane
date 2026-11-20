// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsigsalt validates the off-curve address of a TEAL-compiled
// LogicSig whose security rests on program authorization rather than an
// Ed25519 public key. It never searches for or patches a salt: algod's TEAL v13
// assembler salts a program, and an unsalted program must already derive an
// off-curve address.
package lsigsalt

import (
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ErrUnsaltedAddressOnCurve indicates that an unsalted LogicSig bytecode
// derives an address that is also a valid Ed25519 public key.
var ErrUnsaltedAddressOnCurve = errors.New("lsigsalt: unsalted LogicSig address is on-curve")

// Style is a versioned LogicSig provider's derivation contract: how its
// compiled program gets an off-curve address.
type Style string

const (
	// StyleNone uses no salt. The compiled bytecode is used unchanged and must
	// already derive an off-curve LogicSig address.
	StyleNone Style = "none"

	// StyleAlgodAutoSalt delegates the off-curve search to the TEAL v13
	// assembler. APlane treats the compiler-returned bytecode as authoritative,
	// verifies its reported address, and never patches it locally.
	StyleAlgodAutoSalt Style = "algod_v13_auto_salt"
)

// FindResult is a derived LogicSig program with its off-curve address.
type FindResult struct {
	Bytecode           []byte
	Address            types.Address
	Counter            byte
	CompilerAutoSalted bool
}

// IsOnCurve reports whether addr decodes to a valid Ed25519 curve point and
// could therefore be used as an Ed25519 public key.
func IsOnCurve(addr [32]byte) bool {
	_, err := new(edwards25519.Point).SetBytes(addr[:])
	return err == nil
}

// UseUnmodifiedOffCurve returns the address for bytecode as it is. It fails if
// that address is on-curve, preserving APlane's persisted LogicSig key-file
// invariant for templates with no salt. Counter is zero: an unsalted key file
// records salt_counter 0.
func UseUnmodifiedOffCurve(bytecode []byte) (FindResult, error) {
	addr, err := deriveLogicSigAddress(bytecode)
	if err != nil {
		return FindResult{}, err
	}
	if IsOnCurve(addr) {
		return FindResult{}, ErrUnsaltedAddressOnCurve
	}
	return FindResult{
		Bytecode: append([]byte(nil), bytecode...),
		Address:  addr,
		Counter:  0,
	}, nil
}

// UseCompilerAutoSalted validates the final TEAL v13 bytecode returned by
// algod. The reported hash is checked independently against the address APlane
// derives from the returned bytes, and the resulting address must be
// off-curve. No assembler salting algorithm is reproduced here.
func UseCompilerAutoSalted(bytecode []byte, reportedHash string) (FindResult, error) {
	if len(bytecode) == 0 {
		return FindResult{}, fmt.Errorf("compiler returned empty LogicSig bytecode")
	}
	version, _, err := tealVersionVarint(bytecode)
	if err != nil {
		return FindResult{}, fmt.Errorf("compiler returned invalid LogicSig bytecode version: %w", err)
	}
	if version < 13 {
		return FindResult{}, fmt.Errorf("compiler auto-salt requires final TEAL v13+ bytecode, got v%d", version)
	}
	if reportedHash == "" {
		return FindResult{}, fmt.Errorf("compiler returned an empty LogicSig hash")
	}
	reported, err := types.DecodeAddress(reportedHash)
	if err != nil {
		return FindResult{}, fmt.Errorf("compiler returned invalid LogicSig hash: %w", err)
	}
	derived, err := deriveLogicSigAddress(bytecode)
	if err != nil {
		return FindResult{}, err
	}
	if reported != derived {
		return FindResult{}, fmt.Errorf("compiler LogicSig hash %s does not match locally derived address %s", reportedHash, derived.String())
	}
	if IsOnCurve(derived) {
		return FindResult{}, ErrUnsaltedAddressOnCurve
	}
	return FindResult{
		Bytecode:           append([]byte(nil), bytecode...),
		Address:            derived,
		CompilerAutoSalted: true,
	}, nil
}

func tealVersionVarint(bytecode []byte) (uint64, int, error) {
	version, n := binary.Uvarint(bytecode)
	switch {
	case n > 0:
		if version == 0 {
			return 0, 0, fmt.Errorf("TEAL version varint is zero")
		}
		return version, n, nil
	case n == 0:
		return 0, 0, fmt.Errorf("TEAL version varint is truncated")
	default:
		return 0, 0, fmt.Errorf("TEAL version varint is malformed")
	}
}

func deriveLogicSigAddress(bytecode []byte) (types.Address, error) {
	lsig := crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	return lsig.Address()
}
