// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/signerops"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func testSeed() []byte {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func TestECDSAK1V1SignAndBuildArgs(t *testing.T) {
	dsa := &ECDSAK1V1{}
	ops := signerops.New(nil)
	pub, priv, err := ops.GenerateKeypair(testSeed())
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}
	if len(pub) != 64 {
		t.Fatalf("public key length = %d, want 64", len(pub))
	}
	if len(priv) != 32 {
		t.Fatalf("private key length = %d, want 32", len(priv))
	}

	msg := sha256.Sum256([]byte("ecdsak1 signing test"))
	sig, err := ops.Sign(priv, msg[:])
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}

	args, err := dsa.BuildArgs(sig, nil)
	if err != nil {
		t.Fatalf("BuildArgs() error: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("BuildArgs() arg count = %d, want 2", len(args))
	}
	if len(args[0]) != 32 || len(args[1]) != 32 {
		t.Fatalf("BuildArgs() arg sizes = %d/%d, want 32/32", len(args[0]), len(args[1]))
	}
}

func TestECDSAK1V1GenerateTEAL(t *testing.T) {
	dsa := &ECDSAK1V1{}
	pub, _, err := signerops.New(nil).GenerateKeypair(testSeed())
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	teal, err := dsa.GenerateTEAL(pub, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error: %v", err)
	}

	checks := []string{"#pragma version 12", "bytecblock", "txn TxID", "ecdsa_verify Secp256k1"}
	for _, want := range checks {
		if !strings.Contains(teal, want) {
			t.Fatalf("TEAL missing %q", want)
		}
	}
	preamble, _ := lsigsalt.StylePushbytes.SourcePreamble()
	if strings.Contains(teal, strings.TrimSpace(preamble)) {
		t.Fatalf("TEAL should not use pushbytes salt style:\n%s", teal)
	}
}

func TestECDSAK1V1DeriveLsigRequiresClient(t *testing.T) {
	dsa := &ECDSAK1V1{}
	pub, _, err := signerops.New(nil).GenerateKeypair(testSeed())
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	_, _, err = dsa.DeriveLsig(context.Background(), pub, nil)
	if err == nil {
		t.Fatal("expected error when algod client is not set")
	}
	if !strings.Contains(err.Error(), "algod client not set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestECDSAK1V1AlgodClientAccessIsRaceSafe(t *testing.T) {
	dsa := &ECDSAK1V1{}
	pub := make([]byte, family.PublicKeySize)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				dsa.SetAlgodClient(nil)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = dsa.DeriveLsig(context.Background(), pub, nil)
				_, _ = dsa.DeriveLsigWithSalt(context.Background(), pub, nil)
			}
		}()
	}
	wg.Wait()
}

func TestECDSAK1V1SaltDerivationGolden(t *testing.T) {
	dsa := &ECDSAK1V1{}
	pub, _, err := signerops.New(nil).GenerateKeypair(testSeed())
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	teal, err := dsa.GenerateTEAL(pub, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	compiled := ecdsaK1GoldenCompiledBytecode(pub)
	offset, err := lsigsalt.BytecblockPreambleLocator(compiled)
	if err != nil {
		t.Fatalf("BytecblockPreambleLocator() error = %v", err)
	}
	if offset != 4 {
		t.Fatalf("BytecblockPreambleLocator() = %d, want 4", offset)
	}
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, ecdsaK1CompileMock{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	salted, err := dsa.DeriveLsigWithSalt(context.Background(), pub, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if lsigsalt.IsOnCurve(salted.Address) {
		t.Fatalf("DeriveLsigWithSalt() returned on-curve address %s", salted.Address.String())
	}

	assertGolden(t, "teal hash", sha256Hex([]byte(teal)), "9eeac5098c939ff43c1e3707d5ca1d5e6e5b3d86e204f554a1abadc420aa65dc")
	assertGolden(t, "pre-salt bytecode hash", sha256Hex(compiled), "0f2d14364d22da2981d4b00f9ca84f064b8e55e694c77fbd2defd075d46ddbe1")
	assertGolden(t, "salt counter", hex.EncodeToString([]byte{salted.Counter}), "00")
	assertGolden(t, "derived address", salted.Address.String(), "TE6OYM4G4PIHVI2PYHEA3GIIF3PZ56LVA64GI2KQ7TUNGBQEY4O4I6VBOY")
}

// TestECDSAK1V1SignVerifies proves that the (pub, priv, sig, msg) quadruple
// produced by ECDSAK1V1.GenerateKeypair and Sign is mutually consistent and
// matches what TEAL's `ecdsa_verify Secp256k1` opcode will accept. Byte-length
// checks in TestECDSAK1V1SignAndBuildArgs would miss swapped R/S halves, a
// wrong 32-byte digest being signed, a non-low-S signature, or a bad public-key
// serialization — all four regress this test.
//
// Verification is routed through BuildArgs so the test also pins the LogicSig
// argument ordering: a regression in BuildSignatureArgs that emitted [s, r]
// would still produce a well-formed 64-byte blob but would make args[0] and
// args[1] swap roles, causing off-chain Verify (which mirrors TEAL's consumption
// order) to fail.
func TestECDSAK1V1SignVerifies(t *testing.T) {
	dsa := &ECDSAK1V1{}
	ops := signerops.New(nil)
	pub, priv, err := ops.GenerateKeypair(testSeed())
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	msg := sha256.Sum256([]byte("ecdsak1 sign-verify round trip"))
	sig, err := ops.Sign(priv, msg[:])
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}

	// Build the LogicSig args the way apshell / apsigner would at runtime.
	// The TEAL template consumes arg 0 as R and arg 1 as S (AVM pops the
	// ecdsa_verify stack in Y, X, S, R, Data order), so a future regression
	// that swapped the roles inside BuildSignatureArgs must trip this test.
	args, err := dsa.BuildArgs(sig, nil)
	if err != nil {
		t.Fatalf("BuildArgs() error: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("BuildArgs() arg count = %d, want 2", len(args))
	}
	if !bytes.Equal(args[0], sig[:32]) {
		t.Fatalf("args[0] (R) does not match sig[:32]: %x vs %x", args[0], sig[:32])
	}
	if !bytes.Equal(args[1], sig[32:]) {
		t.Fatalf("args[1] (S) does not match sig[32:]: %x vs %x", args[1], sig[32:])
	}

	// Reconstruct the secp256k1 public key from our 64-byte X||Y encoding
	// by prepending 0x04 for the SEC uncompressed format.
	pubKey, err := secp256k1.ParsePubKey(append([]byte{0x04}, pub...))
	if err != nil {
		t.Fatalf("ParsePubKey() error: %v", err)
	}

	// Parse R and S from the BuildArgs output — not from the raw sig slice —
	// so this test pins the arg ordering contract in addition to the
	// cryptographic one.
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(args[0]); overflow {
		t.Fatal("R scalar overflowed curve order")
	}
	if overflow := s.SetByteSlice(args[1]); overflow {
		t.Fatal("S scalar overflowed curve order")
	}
	decoded := ecdsa.NewSignature(&r, &s)
	if !decoded.Verify(msg[:], pubKey) {
		t.Fatal("signature failed to verify against parsed public key")
	}

	// Independently assert that S is in the low half of the curve order.
	// Verify above may accept high-S signatures mathematically, but the
	// Algorand ecdsa_verify Secp256k1 opcode enforces BIP0062 low-S, so a
	// regression that dropped the canonicalization step would still pass
	// Verify but fail on-chain.
	sBig := new(big.Int).SetBytes(args[1])
	halfN := new(big.Int).Rsh(curveOrder(), 1)
	if sBig.Cmp(halfN) > 0 {
		t.Fatalf("signature S is not low-canonical: %x", args[1])
	}

	// Flipping a message bit must fail verification — defends against a
	// regression where Verify is somehow a no-op (e.g., a stub).
	tampered := msg
	tampered[0] ^= 0x01
	if decoded.Verify(tampered[:], pubKey) {
		t.Fatal("tampered message unexpectedly verified")
	}
}

// curveOrder returns the secp256k1 group order N as a *big.Int. Duplicated
// here rather than reaching into lsig/ecdsak1/family to keep the v1 package
// test-isolated; the constant is a public-domain value.
func curveOrder() *big.Int {
	n, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("failed to initialize secp256k1 curve order")
	}
	return n
}

func ecdsaK1GoldenCompiledBytecode(pub []byte) []byte {
	bytecode := []byte{
		0x0c,
		0x26, 0x01, 0x01, 0x00,
		0x31, 0x17,
		0x2d,
		0x80, byte(len(pub)),
	}
	bytecode = append(bytecode, pub...)
	bytecode = append(bytecode, 0x85)
	return bytecode
}

type ecdsaK1CompileMock struct {
	bytecode []byte
}

func (m ecdsaK1CompileMock) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2/teal/compile" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"unexpected request"}`)),
			Request:    req,
		}, nil
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		return nil, err
	}
	body := `{"result":"` + base64.StdEncoding.EncodeToString(m.bytecode) + `","hash":"unused"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func assertGolden(t *testing.T, label, got, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("%s golden: %s", label, got)
	}
	if got != want {
		t.Fatalf("%s = %s, want %s", label, got, want)
	}
}

// Full DeriveLsig coverage lives in the integration suite:
// TestKeyDerivationRegression/aplane.ecdsak1.v1 exercises the same path against
// the test env's algod client and pins the derived address.
