// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falcontimelock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/lsig/falcon1024/family"

	"filippo.io/edwards25519"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ErrInvalidFalconPublicKey is returned when no suitable counter value can be found
// to derive an address that is not a valid ed25519 public key.
var ErrInvalidFalconPublicKey = errors.New("unsuitable Falcon public key for Algorand address")

var (
	pubkeyPlaceholder = bytes.Repeat([]byte{0x00}, family.PublicKeySize)
	unlockPlaceholder = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	counterPattern    = []byte{0x80, 0x01, 0xff}
)

// DeriveLsig derives a Falcon-1024 timelock LogicSig from a public key and timelock parameters.
func DeriveLsig(publicKey []byte, unlockRound uint64) ([]byte, string, error) {
	if len(publicKey) != family.PublicKeySize {
		return nil, "", fmt.Errorf("invalid public key size: expected %d, got %d",
			family.PublicKeySize, len(publicKey))
	}

	bytecode := make([]byte, len(templateBytecode))
	copy(bytecode, templateBytecode)

	unlockBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(unlockBytes, unlockRound)
	if err := replaceOnce(bytecode, unlockPlaceholder, unlockBytes); err != nil {
		return nil, "", fmt.Errorf("failed to patch unlock_round: %w", err)
	}

	if err := replaceOnce(bytecode, pubkeyPlaceholder, publicKey); err != nil {
		return nil, "", fmt.Errorf("failed to patch public key: %w", err)
	}

	counterIndex, err := findCounterIndex(bytecode)
	if err != nil {
		return nil, "", err
	}

	for counter := 0; counter <= 255; counter++ {
		bytecode[counterIndex] = byte(counter)
		addr, err := deriveAddress(bytecode)
		if err != nil {
			return nil, "", err
		}
		if !isOnTheCurve(addr[:]) {
			return bytecode, addr.String(), nil
		}
	}

	return nil, "", ErrInvalidFalconPublicKey
}

func replaceOnce(data []byte, placeholder []byte, replacement []byte) error {
	if len(placeholder) != len(replacement) {
		return fmt.Errorf("placeholder length %d does not match replacement length %d",
			len(placeholder), len(replacement))
	}

	idx := bytes.Index(data, placeholder)
	if idx < 0 {
		return fmt.Errorf("placeholder not found")
	}
	if next := bytes.Index(data[idx+1:], placeholder); next >= 0 {
		return fmt.Errorf("placeholder found multiple times")
	}

	copy(data[idx:idx+len(replacement)], replacement)
	return nil
}

func findCounterIndex(bytecode []byte) (int, error) {
	idx := bytes.Index(bytecode, counterPattern)
	if idx < 0 {
		return -1, fmt.Errorf("counter placeholder not found")
	}
	if next := bytes.Index(bytecode[idx+1:], counterPattern); next >= 0 {
		return -1, fmt.Errorf("counter placeholder found multiple times")
	}
	return idx + len(counterPattern) - 1, nil
}

func deriveAddress(bytecode []byte) (types.Address, error) {
	lsig := crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	return lsig.Address()
}

// isOnTheCurve returns true if the 32-byte value decodes to a valid edwards25519
// curve point (i.e., could be an ed25519 public key), and false otherwise.
func isOnTheCurve(address []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(address)
	return err == nil
}
