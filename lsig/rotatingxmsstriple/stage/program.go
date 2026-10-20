// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stage builds and parses the stage program of a rotating XMSS
// triple account. A stage program is a frozen TEAL v13 template with six
// constants: the stage's Ed25519 and Falcon-1024 public keys, the XMSS root
// and public seed of the tree the stage belongs to, and the stage's leaf
// index range. It accepts a transaction that rekeys away from the sender,
// does not close out, has a validity window of at most 100 rounds, and
// carries an RFC 8391 XMSS-SHA2_16_256 signature whose index lies in the
// stage's range, an Ed25519 signature and a Falcon-1024 signature, all over
// the TxID.
package stage

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// TEALVersion is the AVM version of every stage program.
	TEALVersion = 13

	// MaxValidityWindow is the largest LastValid - FirstValid the program accepts.
	MaxValidityWindow = 100

	// ConstantSize is the size of the Ed25519 key, the root and the seed.
	ConstantSize = 32

	// FalconPublicKeySize is the embedded Falcon-1024 public key size.
	FalconPublicKeySize = 1793

	// RangeBoundSize is the size of each range bound constant, an eight-byte
	// big-endian integer the program converts with btoi.
	RangeBoundSize = 8

	// XmssSignatureSize, Ed25519SignatureSize and FalconSignatureMaxSize
	// bound arguments 0, 1 and 2.
	XmssSignatureSize      = xmss.SignatureSize
	Ed25519SignatureSize   = 64
	FalconSignatureMaxSize = 1423

	// MaxArgumentBytes is the worst-case total of the three signature
	// arguments.
	MaxArgumentBytes = XmssSignatureSize + Ed25519SignatureSize + FalconSignatureMaxSize

	// IndicesPerStage is the size of a stage's leaf index range; a tree
	// serves StagesPerTree consecutive stages.
	IndicesPerStage = 64
	StagesPerTree   = xmss.Leaves / IndicesPerStage

	// SaltSearchLimit is the number of salt values the v13 assembler tries.
	SaltSearchLimit = 128

	opIntcblock  = 0x20
	saltTailSize = 3

	// SaltedProgramSize is the unsalted program plus the salt tail.
	SaltedProgramSize = UnsaltedProgramSize + saltTailSize

	// Placeholder fill bytes the template was assembled with.
	fillEd25519 = 0x33
	fillFalcon  = 0x44
	fillSeed    = 0x11
	fillRoot    = 0x22
	fillLo      = 0x55
	fillHi      = 0x66
)

var (
	// ErrNoOffCurveSalt reports that every salt candidate hashed on-curve
	// (probability about 2^-128). The stage is unusable and must be skipped.
	ErrNoOffCurveSalt = errors.New("no off-curve salt for rotating xmss stage")

	// ErrInvalidProgram reports bytes that are not a canonical stage program.
	ErrInvalidProgram = errors.New("invalid rotating xmss stage program")
)

// PublicKeys are the constants embedded in a stage program.
type PublicKeys struct {
	Ed25519 [ConstantSize]byte
	Falcon  [FalconPublicKeySize]byte
	Root    [ConstantSize]byte
	Seed    [ConstantSize]byte
	// Lo and Hi bound the stage's leaf indices: Lo <= index < Hi.
	Lo uint64
	Hi uint64
}

// RangeFor returns the tree number and index range of stage n.
func RangeFor(stage uint64) (tree uint64, lo, hi uint64) {
	tree = stage / StagesPerTree
	lo = (stage % StagesPerTree) * IndicesPerStage
	return tree, lo, lo + IndicesPerStage
}

// Program is a final, off-curve stage program and its address.
type Program struct {
	Bytecode []byte
	Address  types.Address
	Salted   bool
	Salt     byte
}

// OpcodeCost is the cost of an accepting run that performs steps chain
// steps (xmss.VerifySteps of the signature), salted or not.
func OpcodeCost(steps int) uint64 {
	return uint64(BaseOpcodeCost + StepOpcodeCost*steps)
}

// offsets of the constant slots in the template, found once at init.
var (
	ed25519KeyOffset int
	falconKeyOffset  int
	seedOffset       int
	rootOffset       int
	loOffset         int
	hiOffset         int
)

func init() {
	find := func(fill byte, size int) int {
		run := bytes.Repeat([]byte{fill}, size)
		off := bytes.Index(template[:], run)
		if off < 0 || bytes.Contains(template[off+1:], run) {
			panic(fmt.Sprintf("rotating xmss stage template: placeholder %#x x%d is not unique", fill, size))
		}
		return off
	}
	ed25519KeyOffset = find(fillEd25519, ConstantSize)
	falconKeyOffset = find(fillFalcon, FalconPublicKeySize)
	seedOffset = find(fillSeed, ConstantSize)
	rootOffset = find(fillRoot, ConstantSize)
	loOffset = find(fillLo, RangeBoundSize)
	hiOffset = find(fillHi, RangeBoundSize)
}

// Build assembles the stage program for keys. If the unsalted program's
// address is on-curve, it appends intcblock 1 <salt> with the first salt in
// [0, 128) that yields an off-curve address, exactly as the v13 assembler does.
func Build(keys *PublicKeys) (Program, error) {
	if keys.Lo >= keys.Hi || keys.Hi > xmss.Leaves {
		return Program{}, fmt.Errorf("%w: range [%d, %d)", ErrInvalidProgram, keys.Lo, keys.Hi)
	}
	base := make([]byte, UnsaltedProgramSize, SaltedProgramSize)
	copy(base, template[:])
	copy(base[ed25519KeyOffset:], keys.Ed25519[:])
	copy(base[falconKeyOffset:], keys.Falcon[:])
	copy(base[seedOffset:], keys.Seed[:])
	copy(base[rootOffset:], keys.Root[:])
	binary.BigEndian.PutUint64(base[loOffset:], keys.Lo)
	binary.BigEndian.PutUint64(base[hiOffset:], keys.Hi)

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
	copy(keys.Seed[:], bytecode[seedOffset:seedOffset+ConstantSize])
	copy(keys.Root[:], bytecode[rootOffset:rootOffset+ConstantSize])
	keys.Lo = binary.BigEndian.Uint64(bytecode[loOffset:])
	keys.Hi = binary.BigEndian.Uint64(bytecode[hiOffset:])

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
// template was assembled.
//
// Scratch slots: 0 hashed message, 1 chain index, 2 running checksum,
// 3 chain ends then L-tree nodes, 4 current chain element, 5 step, 6 digit,
// 7 chain address prefix, 8 leaf index, 9 PRF prefix (toByte(3) || SEED),
// 10 toByte(0) (also the source of every zero run), 11 toByte(1), 12 root,
// 13 OTS address prefix, 14 L-tree or hash-tree address prefix, 15 L-tree
// length, 16 L-tree height or path level, 17 key, 18 masked left node,
// 19 current node, 20 L-tree pair index or path offset, 22 chain step
// address, 23 node address, 24 left input, 25 right input.
func TEALSource(keys *PublicKeys) string {
	var lo, hi [RangeBoundSize]byte
	binary.BigEndian.PutUint64(lo[:], keys.Lo)
	binary.BigEndian.PutUint64(hi[:], keys.Hi)
	var prfPrefix [2 * ConstantSize]byte
	prfPrefix[ConstantSize-1] = 3
	copy(prfPrefix[ConstantSize:], keys.Seed[:])
	return fmt.Sprintf(tealTemplate,
		hex.EncodeToString(keys.Ed25519[:]),
		hex.EncodeToString(keys.Falcon[:]),
		hex.EncodeToString(lo[:]),
		hex.EncodeToString(hi[:]),
		hex.EncodeToString(prfPrefix[:]),
		hex.EncodeToString(keys.Root[:]),
	)
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
pushint 2692
==
assert
arg 0
extract 0 4
btoi
store 8
load 8
pushbytes 0x%s
btoi
>=
assert
load 8
pushbytes 0x%s
btoi
<
assert
pushbytes 0x%s
store 9
pushbytes 0x0000000000000000000000000000000000000000000000000000000000000000
store 10
load 10
extract 0 31
pushbytes 0x01
concat
store 11
pushbytes 0x%s
store 12
load 10
extract 0 31
pushbytes 0x02
concat
arg 0
extract 4 32
concat
load 12
concat
load 10
extract 0 24
load 8
itob
concat
concat
txn TxID
concat
sha256
store 0
load 10
extract 0 16
load 8
itob
extract 4 4
concat
store 13
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
pushint 36
+
pushint 32
extract3
store 4
load 6
store 5
load 13
load 1
itob
extract 4 4
concat
store 7
step_loop:
load 5
pushint 15
<
bz step_done
load 7
load 5
itob
extract 4 4
concat
store 22
load 22
pushbytes 0x00000000
concat
callsub prf
store 17
load 22
pushbytes 0x00000001
concat
callsub prf
load 4
b^
load 10
load 17
concat
swap
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
load 10
extract 0 12
pushbytes 0x00000001
concat
load 8
itob
extract 4 4
concat
store 14
pushint 67
store 15
pushint 0
store 16
ltree_loop:
load 15
pushint 1
>
bz ltree_done
pushint 0
store 20
ltree_pairs:
load 20
load 15
pushint 2
/
<
bz ltree_pairs_done
load 14
load 16
itob
extract 4 4
concat
load 20
itob
extract 4 4
concat
store 23
load 3
load 20
pushint 64
*
pushint 32
extract3
store 24
load 3
load 20
pushint 64
*
pushint 32
+
pushint 32
extract3
store 25
callsub hnode
load 3
load 20
pushint 32
*
load 19
replace3
store 3
load 20
pushint 1
+
store 20
b ltree_pairs
ltree_pairs_done:
load 15
pushint 1
&
bz ltree_even
load 3
load 15
pushint 2
/
pushint 32
*
load 3
load 15
pushint 1
-
pushint 32
*
pushint 32
extract3
replace3
store 3
load 15
pushint 2
/
pushint 1
+
store 15
b ltree_next
ltree_even:
load 15
pushint 2
/
store 15
ltree_next:
load 16
pushint 1
+
store 16
b ltree_loop
ltree_done:
load 3
extract 0 32
store 19
load 10
extract 0 20
pushint 15
pushbytes 0x02
replace3
store 14
load 8
store 20
pushint 0
store 16
auth_loop:
load 16
pushint 16
<
bz auth_done
load 14
load 16
itob
extract 4 4
concat
load 20
pushint 1
shr
itob
extract 4 4
concat
store 23
load 20
pushint 1
&
bz auth_left
arg 0
load 16
pushint 32
*
pushint 2180
+
pushint 32
extract3
store 24
load 19
store 25
b auth_hash
auth_left:
load 19
store 24
arg 0
load 16
pushint 32
*
pushint 2180
+
pushint 32
extract3
store 25
b auth_hash
auth_hash:
callsub hnode
load 20
pushint 1
shr
store 20
load 16
pushint 1
+
store 16
b auth_loop
auth_done:
load 19
load 12
==
return
prf:
load 9
swap
concat
sha256
retsub
hnode:
load 23
pushbytes 0x00000000
concat
callsub prf
store 17
load 23
pushbytes 0x00000001
concat
callsub prf
load 24
b^
store 18
load 23
pushbytes 0x00000002
concat
callsub prf
load 25
b^
load 11
load 17
concat
load 18
concat
swap
concat
sha256
store 19
retsub
`

const (
	// BaseOpcodeCost is the cost of an accepting run before any chain step:
	// the guards, ed25519verify_bare (1,900), falcon_verify (1,700), the
	// message hash, the loop bookkeeping of all 67 chains, the L-tree and
	// the 16-level authentication path. StepOpcodeCost is the cost of one
	// chain step: two PRF calls and the masked F, three sha256 at 35 each,
	// plus the subroutine and bookkeeping opcodes. The LocalNet test confirms
	// both against the node's budget report.
	// Both branches of the path loop cost the same, so the only input the
	// cost depends on is the step count. The salt tail follows the final
	// return and never executes, so a salted program costs the same.
	BaseOpcodeCost = 27_062
	StepOpcodeCost = 150

	// MaxOpcodeCost is the cost of the most expensive accepting run.
	MaxOpcodeCost = BaseOpcodeCost + StepOpcodeCost*xmss.MaxVerifySteps
)
