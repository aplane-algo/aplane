// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsigsalttest builds off-curve LogicSig programs for tests.
package lsigsalttest

import (
	"slices"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

// OffCurve returns bytecode with the byte at offset set to the first value
// whose LogicSig address is off the curve, as lsigsalt.UseUnmodifiedOffCurve
// accepts it, so a test can store or compile it in place of a derived program.
// The input is not changed.
func OffCurve(t testing.TB, bytecode []byte, offset int) lsigsalt.FindResult {
	t.Helper()
	program := slices.Clone(bytecode)
	for value := range 256 {
		program[offset] = byte(value)
		if result, err := lsigsalt.UseUnmodifiedOffCurve(program); err == nil {
			return result
		}
	}
	t.Fatalf("no value at offset %d puts the LogicSig address of %x off the curve", offset, bytecode)
	return lsigsalt.FindResult{}
}

// OnCurve returns bytecode with the byte at offset set to the first value
// whose LogicSig address is on the curve, and that address, so a test can hand
// a create path a program it must refuse. The input is not changed.
func OnCurve(t testing.TB, bytecode []byte, offset int) ([]byte, types.Address) {
	t.Helper()
	program := slices.Clone(bytecode)
	for value := range 256 {
		program[offset] = byte(value)
		if address := crypto.LogicSigAddress(types.LogicSig{Logic: program}); lsigsalt.IsOnCurve(address) {
			return program, address
		}
	}
	t.Fatalf("no value at offset %d puts the LogicSig address of %x on the curve", offset, bytecode)
	return nil, types.Address{}
}
