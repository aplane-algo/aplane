// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	reference "github.com/aplane-algo/aplane/lsig/falcon1024/v1/reference"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

func TestFalcon1024V1_KeyType(t *testing.T) {
	f := &Falcon1024V1{}
	if f.KeyType() != "aplane.falcon1024.v1" {
		t.Errorf("KeyType() = %q, want %q", f.KeyType(), "aplane.falcon1024.v1")
	}
}

func TestFalcon1024V1_Family(t *testing.T) {
	f := &Falcon1024V1{}
	if f.Family() != family.Name {
		t.Errorf("Family() = %q, want %q", f.Family(), family.Name)
	}
}

func TestFalcon1024V1_Version(t *testing.T) {
	f := &Falcon1024V1{}
	if f.Version() != 1 {
		t.Errorf("Version() = %d, want 1", f.Version())
	}
}

func TestFalcon1024V1GenerateTEALUsesReferenceSaltStyle(t *testing.T) {
	f := &Falcon1024V1{}
	pubKey := make([]byte, family.PublicKeySize)

	teal, err := f.GenerateTEAL(pubKey, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, "bytecblock 0x00") {
		t.Fatalf("GenerateTEAL() missing bytecblock salt style:\n%s", teal)
	}
	preamble, _ := lsigsalt.StylePushbytes.SourcePreamble()
	if strings.Contains(teal, strings.TrimSpace(preamble)) {
		t.Fatalf("GenerateTEAL() should not use pushbytes salt style:\n%s", teal)
	}
}

func TestFalcon1024V1SaltDerivationGolden(t *testing.T) {
	f := &Falcon1024V1{}
	pubKey := falconTestPublicKey(t)

	teal, err := f.GenerateTEAL(pubKey, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	compiled := falconV1PreSaltBytecode(pubKey)
	offset, err := lsigsalt.BytecblockPreambleLocator(compiled)
	if err != nil {
		t.Fatalf("BytecblockPreambleLocator() error = %v", err)
	}
	if offset != 4 {
		t.Fatalf("BytecblockPreambleLocator() = %d, want 4", offset)
	}
	salted, err := lsigsalt.FindOffCurve(compiled, lsigsalt.BytecblockPreambleLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}

	var pub falcongo.PublicKey
	copy(pub[:], pubKey)
	referenceAcct, err := reference.DerivePQLogicSig(pub)
	if err != nil {
		t.Fatalf("reference DerivePQLogicSig() error = %v", err)
	}
	referenceAddr, err := referenceAcct.Address()
	if err != nil {
		t.Fatalf("reference Address() error = %v", err)
	}
	if !bytes.Equal(salted.Bytecode, referenceAcct.Lsig.Logic) || salted.Address != referenceAddr {
		t.Fatalf("salted derivation differs from reference")
	}

	assertGolden(t, "teal hash", sha256Hex([]byte(teal)), "2dd97ae616e3889a6203bef8e1fcb59ccdf9dbac5ad121b97585cb09f98794b0")
	assertGolden(t, "pre-salt bytecode hash", sha256Hex(compiled), "a02b4961c86e1081afa95458e76ba2a5f35be03b552f9521265c2350fdb0bc68")
	assertGolden(t, "salt counter", hex.EncodeToString([]byte{salted.Counter}), "03")
	assertGolden(t, "derived address", salted.Address.String(), "MSPG5XNFIFHRROJAWHDTDZBXUN4G4YCCVGRTRNH3WO3UKB22W3XWOUFHG4")
}

func TestFalcon1024V1PatchedBytecodeMatchesCounterSourceCompile(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	f := &Falcon1024V1{}
	pubKey := falconTestPublicKey(t)
	teal, err := f.GenerateTEAL(pubKey, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	compiled := compileTEALForSaltTest(t, client, teal)
	offset, err := lsigsalt.BytecblockPreambleLocator(compiled)
	if err != nil {
		t.Fatalf("BytecblockPreambleLocator() error = %v", err)
	}
	salted, err := lsigsalt.FindOffCurve(compiled, lsigsalt.BytecblockPreambleLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	counterSource := strings.Replace(teal, "bytecblock 0x00", fmt.Sprintf("bytecblock 0x%02x", salted.Counter), 1)
	counterCompiled := compileTEALForSaltTest(t, client, counterSource)

	if !bytes.Equal(counterCompiled, salted.Bytecode) {
		t.Fatalf("compiled counter source does not match patched bytecode")
	}
	assertOnlyOffsetChanged(t, compiled, salted.Bytecode, offset)
}

func TestFalcon1024V1_DeriveLsig_RequiresAlgod(t *testing.T) {
	f := &Falcon1024V1{} // No algod client set

	seed := make([]byte, 64)
	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Should fail without algod client
	_, _, err = f.DeriveLsig(context.Background(), pubKey, nil)
	if err == nil {
		t.Error("DeriveLsig() should fail without algod client")
	}
	if !strings.Contains(err.Error(), "algod client not set") {
		t.Errorf("Expected 'algod client not set' error, got: %v", err)
	}
}

func falconTestPublicKey(t *testing.T) []byte {
	t.Helper()

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return pubKey
}

func falconV1PreSaltBytecode(pubKey []byte) []byte {
	bytecode := []byte{
		0x0c,
		0x26, 0x01, 0x01, 0x00,
		0x31, 0x17,
		0x2d,
		0x80, 0x81, 0x0e,
	}
	bytecode = append(bytecode, pubKey...)
	bytecode = append(bytecode, 0x85)
	return bytecode
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func compileTEALForSaltTest(t *testing.T, client *algod.Client, teal string) []byte {
	t.Helper()

	result, err := client.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return bytecode
}

func assertOnlyOffsetChanged(t *testing.T, before, after []byte, offset int) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("patched bytecode length = %d, want %d", len(after), len(before))
	}
	for i := range before {
		if i == offset {
			continue
		}
		if before[i] != after[i] {
			t.Fatalf("byte offset %d changed: got %x want %x", i, after[i], before[i])
		}
	}
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

func TestFalcon1024V1_DeriveLsig(t *testing.T) {
	// Create algod client
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	f := &Falcon1024V1{}
	f.SetAlgodClient(client)

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive LogicSig
	bytecode, addr, err := f.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() error: %v", err)
	}

	if len(bytecode) != 1805 {
		t.Errorf("Bytecode length = %d, want 1805", len(bytecode))
	}

	if addr == "" {
		t.Error("Address should not be empty")
	}
	salted, err := f.DeriveLsigWithSalt(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error: %v", err)
	}
	if !bytes.Equal(bytecode, salted.Bytecode) || addr != salted.Address.String() {
		t.Fatalf("DeriveLsigWithSalt() = (%x, %s), want (%x, %s)", salted.Bytecode, salted.Address.String(), bytecode, addr)
	}
	if lsigsalt.IsOnCurve(salted.Address) {
		t.Fatalf("DeriveLsigWithSalt() returned on-curve address %s", salted.Address.String())
	}

	// Verify determinism
	bytecode2, addr2, err := f.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() second call error: %v", err)
	}

	if addr != addr2 {
		t.Errorf("Address derivation not deterministic: %s != %s", addr, addr2)
	}

	if !bytes.Equal(bytecode, bytecode2) {
		t.Error("Bytecode derivation not deterministic")
	}

	t.Logf("Derived address: %s", addr)
}

// TestFalcon1024V1_MatchesPrecompiledV1 verifies that the composed system produces
// identical bytecode to the frozen precompiled v1 derivation.
func TestFalcon1024V1_MatchesPrecompiledV1(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	f := &Falcon1024V1{}
	f.SetAlgodClient(client)

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive using Falcon1024V1 (composed system)
	composedBytecode, composedAddr, err := f.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("Composed DeriveLsig() error: %v", err)
	}

	// Derive using precompiled v1 directly (frozen derivation)
	var pub falcongo.PublicKey
	copy(pub[:], pubKey)
	lsigAcct, err := reference.DerivePQLogicSig(pub)
	if err != nil {
		t.Fatalf("Precompiled DerivePQLogicSig() error: %v", err)
	}
	precompiledBytecode := lsigAcct.Lsig.Logic
	precompiledAddrTyped, err := lsigAcct.Address()
	if err != nil {
		t.Fatalf("Address() error: %v", err)
	}
	precompiledAddr := precompiledAddrTyped.String()

	// Compare
	t.Logf("Precompiled v1: %s (%d bytes)", precompiledAddr, len(precompiledBytecode))
	t.Logf("Composed:       %s (%d bytes)", composedAddr, len(composedBytecode))

	if precompiledAddr != composedAddr {
		t.Errorf("Addresses differ:\n  precompiled: %s\n  composed: %s", precompiledAddr, composedAddr)
	}

	if !bytes.Equal(precompiledBytecode, composedBytecode) {
		t.Errorf("Bytecode differs:\n  precompiled len: %d\n  composed len: %d",
			len(precompiledBytecode), len(composedBytecode))
	}
}

// TestZeroSuffixMatchesStandardFalcon verifies that a composed provider
// with no TEAL suffix produces identical bytecode to standard aplane.falcon1024.v1.
func TestZeroSuffixMatchesStandardFalcon(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Create a composed provider with NO TEAL suffix (using the factory)
	pureComposed := newFalconV1Composed()
	pureComposed.SetAlgodClient(client)

	// Generate keypair from same seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive using precompiled v1 (the original frozen derivation)
	var pub falcongo.PublicKey
	copy(pub[:], pubKey)
	lsigAcct, err := reference.DerivePQLogicSig(pub)
	if err != nil {
		t.Fatalf("Standard DerivePQLogicSig() error: %v", err)
	}
	standardBytecode := lsigAcct.Lsig.Logic
	standardAddrTyped, err := lsigAcct.Address()
	if err != nil {
		t.Fatalf("Address() error: %v", err)
	}
	standardAddr := standardAddrTyped.String()

	// Derive using composed with no TEAL suffix
	composedBytecode, composedAddr, err := pureComposed.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("Composed DeriveLsig() error: %v", err)
	}

	// Compare
	t.Logf("Standard aplane.falcon1024.v1 (precompiled):")
	t.Logf("  Address: %s", standardAddr)
	t.Logf("  Bytecode length: %d bytes", len(standardBytecode))
	t.Logf("  First 20 bytes: %x", standardBytecode[:20])

	t.Logf("Composed with no TEAL suffix:")
	t.Logf("  Address: %s", composedAddr)
	t.Logf("  Bytecode length: %d bytes", len(composedBytecode))
	t.Logf("  First 20 bytes: %x", composedBytecode[:20])

	if standardAddr != composedAddr {
		t.Errorf("Addresses differ:\n  standard: %s\n  composed: %s", standardAddr, composedAddr)
	}

	if !bytes.Equal(standardBytecode, composedBytecode) {
		t.Errorf("Bytecode differs:\n  standard len: %d\n  composed len: %d",
			len(standardBytecode), len(composedBytecode))
	}
}
