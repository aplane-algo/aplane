// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stage builds and parses the per-stage LogicSig program of the
// aplane.rotating-triple-wots.v1 key type.
//
// Every stage runs the same TEAL v13 program; only four embedded constants
// differ: the Ed25519 public key, the Falcon-1024 public key, the stage tweak
// T and the WOTS public key. The source is TEALSource. In order it requires a
// non-zero rekey to another address, no close-out, a validity window of at
// most 100 rounds, an Ed25519 signature over the TxID (argument 1), a
// Falcon-1024 signature over the TxID (argument 2), and a WOTS-w16 signature
// over the TxID (argument 0, exactly 2,144 bytes) whose 67 chains, each advanced from
// the signature element to step 15 with sha256(T || itob(chain*256 + step) ||
// x), hash to the WOTS public key. The WOTS part is the
// aplane.rotating-wots-hybrid.v1 program unchanged.
//
// Bytecode is assembled locally by copying the four constants into a frozen
// byte template, then salted off-curve with the same trailing-intcblock rule
// the v13 assembler applies, so stages can be derived offline and in bulk
// without trusting a node for addresses. The assembler cross-check test pins
// this package to stock algod output.
//
// This package is client-safe: it holds no private keys and does not link the
// CGo Falcon implementation.
package stage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// TEALVersion is the AVM version of every stage program.
	TEALVersion = 13

	// MaxValidityWindow is the largest LastValid - FirstValid the program accepts.
	MaxValidityWindow = 100

	// ConstantSize is the size of the Ed25519 key, the tweak and the WOTS key.
	ConstantSize = 32

	// FalconPublicKeySize is the embedded Falcon-1024 public key size.
	FalconPublicKeySize = 1793

	// WotsSignatureSize, Ed25519SignatureSize and FalconSignatureMaxSize
	// bound arguments 0, 1 and 2.
	WotsSignatureSize      = wots.SignatureSize
	Ed25519SignatureSize   = 64
	FalconSignatureMaxSize = 1423

	// MaxArgumentBytes is the worst-case total of the three signature
	// arguments.
	MaxArgumentBytes = WotsSignatureSize + Ed25519SignatureSize + FalconSignatureMaxSize

	// UnsaltedProgramSize and SaltedProgramSize are the only two program sizes.
	UnsaltedProgramSize = 2100
	SaltedProgramSize   = UnsaltedProgramSize + saltTailSize

	// BaseOpcodeCost is the cost of an accepting run before any chain step:
	// the guards, ed25519verify_bare (1,900), falcon_verify (1,700), the loop
	// bookkeeping of all 67 chains and the final hash. StepOpcodeCost is the
	// cost of one chain step (sha256 at 35 plus 18 single-cost opcodes). The
	// LocalNet test confirms both against the node's budget report.
	BaseOpcodeCost = 7301
	StepOpcodeCost = 53

	// MaxOpcodeCost is the cost of the most expensive accepting run, for a
	// salted program (the trailing intcblock costs one).
	MaxOpcodeCost = BaseOpcodeCost + StepOpcodeCost*wots.MaxVerifySteps + 1

	// SaltSearchLimit is the number of salt values the v13 assembler tries.
	SaltSearchLimit = 128

	opIntcblock  = 0x20
	saltTailSize = 3

	// Offsets of the four constants inside the template.
	ed25519KeyOffset = 33
	falconKeyOffset  = 73
	tweakOffset      = 1991
	wotsKeyOffset    = 2067
)

// template is the stock v13 assembly of TEALSource with placeholder
// constants: 0x33.. for the Ed25519 key, 0x44.. for the Falcon key, 0x11..
// for the tweak, 0x22.. for the WOTS key. It is stored as the bytes before
// and after the Falcon key slot, with the slot filled at init.
var template = func() [UnsaltedProgramSize]byte {
	var t [UnsaltedProgramSize]byte
	n := copy(t[:], templateHead[:])
	n += copy(t[n:], bytes.Repeat([]byte{0x44}, FalconPublicKeySize))
	if n+copy(t[n:], templateTail[:]) != UnsaltedProgramSize {
		panic("rotating triple stage template has the wrong size")
	}
	return t
}()

// templateHead is the template up to the Falcon key slot (it ends with
// pushbytes and the two-byte length 1793).
var templateHead = [falconKeyOffset]byte{
	0x0d, 0x31, 0x20, 0x32, 0x03, 0x13, 0x44, 0x31, 0x20, 0x31, 0x00, 0x13, 0x44, 0x31, 0x09, 0x32,
	0x03, 0x12, 0x44, 0x31, 0x04, 0x31, 0x02, 0x09, 0x81, 0x64, 0x0e, 0x44, 0x31, 0x17, 0x2e, 0x80,
	0x20, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x84, 0x44, 0x31, 0x17, 0x2f, 0x80, 0x81, 0x0e,
}

// templateTail is the template after the Falcon key slot.
var templateTail = [...]byte{
	0x85, 0x44, 0x2d, 0x15, 0x81, 0xe0, 0x10, 0x12, 0x44, 0x31, 0x17, 0x35, 0x00, 0x81, 0x00, 0x35,
	0x01, 0x81, 0x00, 0x35, 0x02, 0x80, 0x00, 0x35, 0x03, 0x34, 0x01, 0x81, 0x43, 0x0c, 0x41, 0xc6,
	0x02, 0x34, 0x01, 0x81, 0x40, 0x0c, 0x41, 0x4a, 0x34, 0x00, 0x34, 0x01, 0x81, 0x02, 0x0a, 0x55,
	0x34, 0x01, 0x81, 0x02, 0x18, 0x41, 0x0a, 0x81, 0x0f, 0x1a, 0x42, 0x06, 0x81, 0x04, 0x91, 0x49,
	0x35, 0x06, 0x81, 0x0f, 0x4c, 0x09, 0x34, 0x02, 0x08, 0x35, 0x02, 0x42, 0x20, 0x34, 0x02, 0x81,
	0x42, 0x34, 0x01, 0x09, 0x81, 0x04, 0x0b, 0x91, 0x81, 0x0f, 0x1a, 0x35, 0x06, 0x2d, 0x34, 0x01,
	0x81, 0x20, 0x0b, 0x81, 0x20, 0x58, 0x35, 0x04, 0x34, 0x06, 0x35, 0x05, 0x34, 0x01, 0x81, 0x80,
	0x02, 0x0b, 0x35, 0x07, 0x34, 0x05, 0x81, 0x0f, 0x0c, 0x41, 0x70, 0x80, 0x20, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x34, 0x07, 0x34,
	0x05, 0x08, 0x16, 0x50, 0x34, 0x04, 0x50, 0x01, 0x35, 0x04, 0x34, 0x05, 0x81, 0x01, 0x08, 0x35,
	0x05, 0x42, 0x79, 0x34, 0x03, 0x34, 0x04, 0x50, 0x35, 0x03, 0x34, 0x01, 0x81, 0x01, 0x08, 0x35,
	0x01, 0x42, 0xcf, 0x02, 0x34, 0x03, 0x01, 0x80, 0x20, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x12,
}

var (
	// ErrNoOffCurveSalt reports that every salt candidate hashed on-curve
	// (probability about 2^-128). The stage is unusable and must be skipped.
	ErrNoOffCurveSalt = errors.New("no off-curve salt for rotating triple stage")

	// ErrInvalidProgram reports bytes that are not a canonical stage program.
	ErrInvalidProgram = errors.New("invalid rotating triple stage program")
)

// PublicKeys are the four constants embedded in a stage program.
type PublicKeys struct {
	Ed25519 [ConstantSize]byte
	Falcon  [FalconPublicKeySize]byte
	Tweak   wots.Tweak
	Wots    wots.PublicKey
}

// Program is a final, off-curve stage program and its address.
type Program struct {
	Bytecode []byte
	Address  types.Address
	Salted   bool
	Salt     byte
}

// OpcodeCost is the cost of an accepting run that performs steps chain
// steps (wots.VerifySteps of the TxID), for an unsalted program.
func OpcodeCost(steps int) uint64 {
	return uint64(BaseOpcodeCost + StepOpcodeCost*steps)
}

// Build assembles the stage program for keys. If the unsalted program's
// address is on-curve, it appends intcblock 1 <salt> with the first salt in
// [0, 128) that yields an off-curve address, exactly as the v13 assembler does.
func Build(keys *PublicKeys) (Program, error) {
	base := make([]byte, UnsaltedProgramSize, SaltedProgramSize)
	copy(base, template[:])
	copy(base[ed25519KeyOffset:], keys.Ed25519[:])
	copy(base[falconKeyOffset:], keys.Falcon[:])
	copy(base[tweakOffset:], keys.Tweak[:])
	copy(base[wotsKeyOffset:], keys.Wots[:])

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
	copy(keys.Tweak[:], bytecode[tweakOffset:tweakOffset+ConstantSize])
	copy(keys.Wots[:], bytecode[wotsKeyOffset:wotsKeyOffset+ConstantSize])

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

// TEALSource is the program's source for keys, exactly as the frozen
// template was assembled. Scratch slots: 0 TxID, 1 chain index, 2 running
// checksum, 3 concatenated chain ends, 4 current element, 5 step, 6 digit,
// 7 chain index times 256.
func TEALSource(keys *PublicKeys) string {
	return fmt.Sprintf(tealTemplate, hex.EncodeToString(keys.Ed25519[:]), hex.EncodeToString(keys.Falcon[:]), hex.EncodeToString(keys.Tweak[:]), hex.EncodeToString(keys.Wots[:]))
}

const tealTemplate = `#pragma version 13
txn RekeyTo
global ZeroAddress
!=
assert
txn RekeyTo
txn Sender
!=
assert
txn CloseRemainderTo
global ZeroAddress
==
assert
txn LastValid
txn FirstValid
-
pushint 100
<=
assert
txn TxID
arg 1
pushbytes 0x%s
ed25519verify_bare
assert
txn TxID
arg 2
pushbytes 0x%s
falcon_verify
assert
arg 0
len
pushint 2144
==
assert
txn TxID
store 0
pushint 0
store 1
pushint 0
store 2
pushbytes 0x
store 3
chain_loop:
load 1
pushint 67
<
bz chains_done
load 1
pushint 64
<
bz checksum_digit
load 0
load 1
pushint 2
/
getbyte
load 1
pushint 2
%%
bz high_nibble
pushint 15
&
b got_digit
high_nibble:
pushint 4
shr
got_digit:
dup
store 6
pushint 15
swap
-
load 2
+
store 2
b have_digit
checksum_digit:
load 2
pushint 66
load 1
-
pushint 4
*
shr
pushint 15
&
store 6
have_digit:
arg 0
load 1
pushint 32
*
pushint 32
extract3
store 4
load 6
store 5
load 1
pushint 256
*
store 7
step_loop:
load 5
pushint 15
<
bz step_done
pushbytes 0x%s
load 7
load 5
+
itob
concat
load 4
concat
sha256
store 4
load 5
pushint 1
+
store 5
b step_loop
step_done:
load 3
load 4
concat
store 3
load 1
pushint 1
+
store 1
b chain_loop
chains_done:
load 3
sha256
pushbytes 0x%s
==
`
