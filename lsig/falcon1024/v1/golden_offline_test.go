// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

// TestFalcon1024V1OfflineGolden pins the account address without a node. The
// fixture is the bytecode algod returned for the key from falconTestPublicKey;
// TestFalcon1024V1CompilerAutoSaltGolden is the live check that algod still
// returns it. A change to the template, the key encoding, or the address
// hashing fails here.
func TestFalcon1024V1OfflineGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden_bytecode.hex")
	if err != nil {
		t.Fatal(err)
	}
	bytecode, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}

	// version 13; txn TxID; arg 0; pushbytes <1793-byte key>; falcon_verify.
	// The key needed no salt, so the program carries no salt bytes.
	pub := falconTestPublicKey(t)
	want := append([]byte{0x0d, 0x31, 0x17, 0x2d, 0x80, 0x81, 0x0e}, pub...)
	want = append(want, 0x85)
	if !bytes.Equal(bytecode, want) {
		t.Fatalf("fixture is not the expected program for the test key (%d bytes)", len(bytecode))
	}

	addr, err := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}.Address()
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "MS4DNTRYOOLQZ4UXK5APVE4XEWMU4CDTUYGOO5UQCWLONDRUP56DZDOBVA" {
		t.Fatalf("address = %s", got)
	}
	if lsigsalt.IsOnCurve(addr) {
		t.Fatal("address decodes as an ed25519 point")
	}
}
