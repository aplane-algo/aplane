// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

const goldenAddress = "MS4DNTRYOOLQZ4UXK5APVE4XEWMU4CDTUYGOO5UQCWLONDRUP56DZDOBVA"

func readGoldenBytecode(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden_bytecode.hex")
	if err != nil {
		t.Fatal(err)
	}
	bytecode, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return bytecode
}

// TestFalcon1024V1OfflineGolden checks that the saved compiler output is the
// program for the test key and hashes to the pinned address.
// TestFalcon1024V1ProductionDerivationOffline ties it to production code, and
// TestFalcon1024V1CompilerAutoSaltGolden is the live check that algod still
// returns it.
func TestFalcon1024V1OfflineGolden(t *testing.T) {
	bytecode := readGoldenBytecode(t)

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
	if got := addr.String(); got != goldenAddress {
		t.Fatalf("address = %s", got)
	}
	if lsigsalt.IsOnCurve(addr) {
		t.Fatal("address decodes as an ed25519 point")
	}
}

// TestFalcon1024V1ProductionDerivationOffline runs the production derivation
// against a stand-in compiler that returns the saved bytecode only if it is
// sent the saved TEAL for the test key. A change to the generated program
// makes the stand-in refuse, so template drift fails here without a node.
func TestFalcon1024V1ProductionDerivationOffline(t *testing.T) {
	wantTEAL, err := os.ReadFile("testdata/golden.teal")
	if err != nil {
		t.Fatal(err)
	}
	bytecode := readGoldenBytecode(t)
	addr, err := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}.Address()
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v2/teal/compile" || !bytes.Equal(body, wantTEAL) {
			http.Error(w, "unexpected TEAL source", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"hash":   addr.String(),
			"result": base64.StdEncoding.EncodeToString(bytecode),
		})
	}))
	defer srv.Close()

	client, err := algod.MakeClient(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	f := &Falcon1024V1{}
	f.SetAlgodClient(client)
	derived, err := f.DeriveLsigWithSalt(context.Background(), falconTestPublicKey(t), nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if !derived.CompilerAutoSalted || derived.Address.String() != goldenAddress || !bytes.Equal(derived.Bytecode, bytecode) {
		t.Fatalf("derived = %d bytes / %s", len(derived.Bytecode), derived.Address.String())
	}
}
