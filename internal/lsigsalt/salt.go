// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsigsalt provides the shared off-curve salting helper for
// TEAL-compiled LogicSigs whose security rests on program authorization rather
// than an Ed25519 public key.
//
// The frozen Falcon v1 reference implementation intentionally keeps its local
// salting code as a test oracle and should not import this package.
package lsigsalt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// MaxIterations is the number of single-byte counter values tried.
const MaxIterations = 256

// ErrNoSuitableCounter indicates that no counter value produced an off-curve
// LogicSig address. With uniformly distributed addresses this should be
// effectively unreachable; in practice it points to a malformed salt slot.
var ErrNoSuitableCounter = errors.New("lsigsalt: no off-curve address after 256 iterations")

// ErrUnsaltedAddressOnCurve indicates that an unsalted LogicSig bytecode
// derives an address that is also a valid Ed25519 public key.
var ErrUnsaltedAddressOnCurve = errors.New("lsigsalt: unsalted LogicSig address is on-curve")

var counterPattern = []byte{0x26, 0x01, 0x01}

// The pushbytes marker includes the salt-style marker version ("_V1_") as
// part of the exact bytes expected by StylePushbytes. A future marker version
// should be selected explicitly by the provider/style contract rather than
// accepted opportunistically by this locator.
var pushbytesMarkerPrefix = []byte("APLANE_LSIG_SALT_V1_")
var pushbytesMarkerSuffix = []byte("_END")

// Style identifies the source-level salt anchor used by a versioned LogicSig
// provider. The style determines both the TEAL preamble emitted before
// compilation and the locator used to patch the compiled bytecode.
type Style string

const (
	// StyleNone uses no generated salt anchor. The compiled bytecode is used
	// unchanged and must already derive an off-curve LogicSig address.
	StyleNone Style = "none"

	// StyleAlgodAutoSalt delegates the off-curve search to the TEAL v13
	// assembler. APlane treats the compiler-returned bytecode as authoritative,
	// verifies its reported address, and never patches it locally.
	StyleAlgodAutoSalt Style = "algod_v13_auto_salt"

	// StyleBytecblock uses an explicit bytecblock salt slot. This is suitable
	// only for provider-owned TEAL whose bytecode foundation intentionally uses
	// this layout.
	StyleBytecblock Style = "bytecblock"

	// StylePushbytes uses a stack-neutral source preamble that compiles to an
	// inline pushbytes literal. This is the safe style for template-backed TEAL
	// because algod remains free to own constant-block layout.
	StylePushbytes Style = "pushbytes"

	// StyleTrailingBytecblock uses a single-byte bytecblock after the program's
	// logical exit. The block remains part of the hashed LogicSig bytecode but
	// is not executed when the program exits before reaching it.
	StyleTrailingBytecblock Style = "trailing_bytecblock"
)

// SourcePreamble returns the TEAL source preamble for style. Trailing styles
// return an empty preamble and should be paired with SourceTrailer.
func (s Style) SourcePreamble() (string, error) {
	switch s {
	case StyleNone, StyleAlgodAutoSalt:
		return "", nil
	case StyleBytecblock:
		return "bytecblock 0x00\n", nil
	case StylePushbytes:
		return "byte 0x" + PushbytesSaltMarkerHex(0) + "\npop\n", nil
	case StyleTrailingBytecblock:
		return "", nil
	default:
		return "", fmt.Errorf("unknown LogicSig salt style %q", s)
	}
}

// SourceTrailer returns the TEAL source trailer for style. Most styles do not
// use a trailer.
func (s Style) SourceTrailer() (string, error) {
	switch s {
	case StyleNone, StyleAlgodAutoSalt, StyleBytecblock, StylePushbytes:
		return "", nil
	case StyleTrailingBytecblock:
		return "bytecblock 0x00\n", nil
	default:
		return "", fmt.Errorf("unknown LogicSig salt style %q", s)
	}
}

// Locator returns the compiled-bytecode salt locator for style.
func (s Style) Locator() (Locator, error) {
	switch s {
	case StyleNone, StyleAlgodAutoSalt:
		return nil, fmt.Errorf("LogicSig salt style %q has no salt locator", s)
	case StyleBytecblock:
		return BytecblockPreambleLocator, nil
	case StylePushbytes:
		return PushbytesMarkerLocator, nil
	case StyleTrailingBytecblock:
		return TrailingBytecblockLocator, nil
	default:
		return nil, fmt.Errorf("unknown LogicSig salt style %q", s)
	}
}

// Locator finds the byte offset of the salt counter in compiled LogicSig
// bytecode.
type Locator func(bytecode []byte) (offset int, err error)

// FindResult is the successful result of an off-curve salt search.
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

// BytecblockLocator is kept as the public bytecblock-style locator name, but
// its semantics are now the strict provider-owned preamble locator. See
// BytecblockPreambleLocator; this function does not perform scan-anywhere
// matching.
func BytecblockLocator(bytecode []byte) (int, error) {
	return BytecblockPreambleLocator(bytecode)
}

// BytecblockPreambleLocator finds the provider-owned compiled `bytecblock 0x00`
// salt slot immediately after the TEAL version varint. It does not scan later
// bytecode for matching byte patterns.
func BytecblockPreambleLocator(bytecode []byte) (int, error) {
	_, versionLen, err := tealVersionVarint(bytecode)
	if err != nil {
		return -1, err
	}
	if len(bytecode) < versionLen+len(counterPattern)+1 {
		return -1, fmt.Errorf("bytecblock salt preamble truncated after TEAL version varint")
	}
	if bytecode[versionLen] != counterPattern[0] ||
		bytecode[versionLen+1] != counterPattern[1] ||
		bytecode[versionLen+2] != counterPattern[2] {
		return -1, fmt.Errorf("bytecblock salt preamble not found immediately after TEAL version varint")
	}
	return versionLen + len(counterPattern), nil
}

// PushbytesSaltMarker returns the source-level marker literal used by the
// pushbytes salt style. The fixed prefix+suffix contribute 24 fixed ASCII
// bytes around the single mutable counter byte, so accidental collision is
// bounded by at most 2^-192 for exact-marker matching.
func PushbytesSaltMarker(counter byte) []byte {
	marker := make([]byte, 0, len(pushbytesMarkerPrefix)+1+len(pushbytesMarkerSuffix))
	marker = append(marker, pushbytesMarkerPrefix...)
	marker = append(marker, counter)
	marker = append(marker, pushbytesMarkerSuffix...)
	return marker
}

// PushbytesSaltMarkerHex returns PushbytesSaltMarker(counter) encoded for TEAL
// source as a byte literal.
func PushbytesSaltMarkerHex(counter byte) string {
	return hex.EncodeToString(PushbytesSaltMarker(counter))
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

// PushbytesLocator is kept as the public pushbytes-style locator name, but its
// semantics are now the generated-marker locator. See PushbytesMarkerLocator;
// this function does not match generic `pushbytes 0x00` instructions.
func PushbytesLocator(bytecode []byte) (int, error) {
	return PushbytesMarkerLocator(bytecode)
}

// PushbytesMarkerLocator finds the single mutable counter byte inside the
// generated pushbytes salt marker. Exactly one marker must be present: a second
// marker, including one forged inside user-authored TEAL bytes, fails closed
// rather than creating an ambiguous patch location.
func PushbytesMarkerLocator(bytecode []byte) (int, error) {
	found := -1
	searchAt := 0
	for {
		prefixAt := bytes.Index(bytecode[searchAt:], pushbytesMarkerPrefix)
		if prefixAt < 0 {
			break
		}
		prefixAt += searchAt
		counterOffset := prefixAt + len(pushbytesMarkerPrefix)
		suffixAt := counterOffset + 1
		suffixEnd := suffixAt + len(pushbytesMarkerSuffix)
		if suffixEnd <= len(bytecode) && bytes.Equal(bytecode[suffixAt:suffixEnd], pushbytesMarkerSuffix) {
			if found >= 0 {
				return -1, fmt.Errorf("multiple pushbytes salt markers found")
			}
			found = counterOffset
		}
		searchAt = prefixAt + 1
	}
	if found < 0 {
		return -1, fmt.Errorf("pushbytes salt marker not found in bytecode")
	}
	return found, nil
}

// TrailingBytecblockLocator finds the mutable counter byte in a final
// `bytecblock 0x00` trailer. It requires the salt block to be the final
// encoded instruction so the locator cannot accidentally match bytecode inside
// the live program body.
func TrailingBytecblockLocator(bytecode []byte) (int, error) {
	if len(bytecode) < len(counterPattern)+1 {
		return -1, fmt.Errorf("trailing bytecblock salt block not found")
	}
	patternStart := len(bytecode) - len(counterPattern) - 1
	if !bytes.Equal(bytecode[patternStart:patternStart+len(counterPattern)], counterPattern) {
		return -1, fmt.Errorf("trailing bytecblock salt block not found at end of bytecode")
	}
	return len(bytecode) - 1, nil
}

// CounterFromBytecode reads the salt counter byte from already-patched
// bytecode using the same locator used for salting.
func CounterFromBytecode(bytecode []byte, locate Locator) (byte, error) {
	if locate == nil {
		return 0, fmt.Errorf("salt locator is nil")
	}
	offset, err := locate(bytecode)
	if err != nil {
		return 0, err
	}
	if offset < 0 || offset >= len(bytecode) {
		return 0, fmt.Errorf("salt counter offset %d out of range for bytecode length %d", offset, len(bytecode))
	}
	return bytecode[offset], nil
}

// FindOffCurve patches the located salt byte through all single-byte counter
// values and returns the first bytecode whose LogicSig address is off-curve.
// The input bytecode is never mutated.
func FindOffCurve(bytecode []byte, locate Locator) (FindResult, error) {
	return findOffCurve(bytecode, locate, deriveLogicSigAddress)
}

// UseUnmodifiedOffCurve returns the address for bytecode without patching any
// salt byte. It fails if that address is on-curve, preserving APlane's
// persisted LogicSig key-file invariant even for templates with no salt anchor.
// Counter is zero only as compatibility metadata for existing key-file storage.
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

// FindOffCurveAtOffset patches the salt byte at offset through all single-byte
// counter values and returns the first bytecode whose LogicSig address is
// off-curve. The input bytecode is never mutated.
func FindOffCurveAtOffset(bytecode []byte, offset int) (FindResult, error) {
	return findOffCurveAtOffset(bytecode, offset, deriveLogicSigAddress)
}

func findOffCurve(
	bytecode []byte,
	locate Locator,
	derive func([]byte) (types.Address, error),
) (FindResult, error) {
	if locate == nil {
		return FindResult{}, fmt.Errorf("salt locator is nil")
	}
	offset, err := locate(bytecode)
	if err != nil {
		return FindResult{}, err
	}
	return findOffCurveAtOffset(bytecode, offset, derive)
}

func findOffCurveAtOffset(
	bytecode []byte,
	offset int,
	derive func([]byte) (types.Address, error),
) (FindResult, error) {
	if offset < 0 || offset >= len(bytecode) {
		return FindResult{}, fmt.Errorf("salt counter offset %d out of range for bytecode length %d", offset, len(bytecode))
	}

	for counter := 0; counter < MaxIterations; counter++ {
		patched := append([]byte(nil), bytecode...)
		patched[offset] = byte(counter)
		addr, err := derive(patched)
		if err != nil {
			return FindResult{}, err
		}
		if !IsOnCurve(addr) {
			return FindResult{
				Bytecode: patched,
				Address:  addr,
				Counter:  byte(counter),
			}, nil
		}
	}

	return FindResult{}, ErrNoSuitableCounter
}

func deriveLogicSigAddress(bytecode []byte) (types.Address, error) {
	lsig := crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	return lsig.Address()
}
