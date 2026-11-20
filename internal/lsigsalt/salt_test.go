// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigsalt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestIsOnCurve(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	var onCurve [32]byte
	copy(onCurve[:], pub)
	if !IsOnCurve(onCurve) {
		t.Fatal("IsOnCurve(valid Ed25519 public key) = false, want true")
	}

	var offCurve [32]byte
	found := false
	for i := 0; i < 1000; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("off-curve-vector-%d", i)))
		if !IsOnCurve(sum) {
			offCurve = sum
			found = true
			break
		}
	}
	if !found {
		t.Fatal("failed to find deterministic off-curve test vector")
	}
	if IsOnCurve(offCurve) {
		t.Fatal("IsOnCurve(off-curve vector) = true, want false")
	}
}

func TestUseUnmodifiedOffCurve(t *testing.T) {
	bytecode := []byte{0x0a, 0x81, 0x00}
	for counter := range 256 {
		bytecode[2] = byte(counter)
		result, err := UseUnmodifiedOffCurve(bytecode)
		if err == nil {
			if !bytes.Equal(result.Bytecode, bytecode) {
				t.Fatalf("UseUnmodifiedOffCurve() bytecode = %x, want %x", result.Bytecode, bytecode)
			}
			if result.Counter != 0 {
				t.Fatalf("UseUnmodifiedOffCurve() counter = %d, want 0", result.Counter)
			}
			if IsOnCurve(result.Address) {
				t.Fatal("UseUnmodifiedOffCurve() returned on-curve address")
			}
			return
		}
		if !errors.Is(err, ErrUnsaltedAddressOnCurve) {
			t.Fatalf("UseUnmodifiedOffCurve() error = %v, want nil or %v", err, ErrUnsaltedAddressOnCurve)
		}
	}
	t.Fatal("failed to find deterministic off-curve bytecode for test")
}

func TestUseCompilerAutoSaltedVerifiesReportedHash(t *testing.T) {
	bytecode := []byte{13, 0x81, 0}
	var valid FindResult
	for counter := range 256 {
		bytecode[2] = byte(counter)
		candidate, err := UseUnmodifiedOffCurve(bytecode)
		if err == nil {
			valid = candidate
			break
		}
		if !errors.Is(err, ErrUnsaltedAddressOnCurve) {
			t.Fatalf("UseUnmodifiedOffCurve() error = %v", err)
		}
	}
	if len(valid.Bytecode) == 0 {
		t.Fatal("failed to find deterministic off-curve bytecode")
	}

	got, err := UseCompilerAutoSalted(valid.Bytecode, valid.Address.String())
	if err != nil {
		t.Fatalf("UseCompilerAutoSalted() error = %v", err)
	}
	if !got.CompilerAutoSalted || got.Address != valid.Address || !bytes.Equal(got.Bytecode, valid.Bytecode) {
		t.Fatalf("UseCompilerAutoSalted() = %+v, want bytecode/address with compiler-auto-salted marker", got)
	}

	other := types.Address{1}
	if _, err := UseCompilerAutoSalted(valid.Bytecode, other.String()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("UseCompilerAutoSalted(mismatched hash) error = %v, want mismatch", err)
	}
	if _, err := UseCompilerAutoSalted(valid.Bytecode, "not-an-address"); err == nil {
		t.Fatal("UseCompilerAutoSalted(invalid hash) error = nil")
	}
	if _, err := UseCompilerAutoSalted(valid.Bytecode, ""); err == nil {
		t.Fatal("UseCompilerAutoSalted(empty hash) error = nil")
	}
}
