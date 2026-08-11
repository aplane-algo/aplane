// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	keygenreg "github.com/aplane-algo/aplane/internal/keygen"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	mnemonicreg "github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1/reference"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// init registers Falcon DSA for tests (avoiding import cycle with dsa/falcon)
func init() {
	// Only register if not already registered
	// Uses unique key type to avoid conflicts with real registrations from other test packages
	if logicsigdsa.Get("aplane.falcon1024.v1") == nil {
		logicsigdsa.Register(&testFalcon1024V1{})
	}
	// Also register the generator now that it's needed
	keygenreg.Register(NewLogicSigGenerator("falcon1024", map[string]LogicSigKeygenOps{
		"falcon1024":           signerops.New(nil),
		"aplane.falcon1024.v1": signerops.New(nil),
	}))
}

// testFalcon1024V1 is a minimal DSA implementation for tests.
// Implements both LogicSigDSA and LSigProvider interfaces.
type testFalcon1024V1 struct{}

// LogicSigDSA interface
func (f *testFalcon1024V1) KeyType() string          { return "aplane.falcon1024.v1" }
func (f *testFalcon1024V1) RoutingFamily() string    { return "falcon1024" }
func (f *testFalcon1024V1) Version() int             { return 1 }
func (f *testFalcon1024V1) CryptoSignatureSize() int { return family.MaxSignatureSize }
func (f *testFalcon1024V1) MnemonicScheme() string   { return "bip39" }
func (f *testFalcon1024V1) MnemonicWordCount() int   { return 24 }
func (f *testFalcon1024V1) DisplayColor() string     { return "33" }

// LSigProvider interface
func (f *testFalcon1024V1) Category() string    { return lsigprovider.CategoryDSALsig }
func (f *testFalcon1024V1) DisplayName() string { return "Falcon-1024" }
func (f *testFalcon1024V1) Description() string { return "Test DSA" }
func (f *testFalcon1024V1) CreationParams() []lsigprovider.ParameterDef {
	return nil
}
func (f *testFalcon1024V1) ValidateCreationParams(params map[string]string) error {
	return nil
}
func (f *testFalcon1024V1) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}
func (f *testFalcon1024V1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required")
	}
	return [][]byte{signature}, nil
}

func (f *testFalcon1024V1) GenerateKeypair(seed []byte) ([]byte, []byte, error) {
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, err
	}
	return kp.PublicKey[:], kp.PrivateKey[:], nil
}

func (f *testFalcon1024V1) DeriveLsig(_ context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	_ = params // Pure Falcon ignores params
	var pub falcongo.PublicKey
	copy(pub[:], publicKey)

	// Use v1 derivation
	lsigAcct, err := v1.DerivePQLogicSig(pub)
	if err != nil {
		return nil, "", err
	}
	addr, err := lsigAcct.Address()
	if err != nil {
		return nil, "", err
	}
	return lsigAcct.Lsig.Logic, addr.String(), nil
}

func (f *testFalcon1024V1) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	bytecode, _, err := f.DeriveLsig(ctx, publicKey, params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	counter, err := lsigsalt.CounterFromBytecode(bytecode, lsigsalt.BytecblockLocator)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	var pub falcongo.PublicKey
	copy(pub[:], publicKey)
	lsigAcct, err := v1.DerivePQLogicSig(pub)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	addr, err := lsigAcct.Address()
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	return lsigsalt.FindResult{
		Bytecode: bytecode,
		Address:  addr,
		Counter:  counter,
	}, nil
}

func (f *testFalcon1024V1) Sign(privateKey []byte, message []byte) ([]byte, error) {
	var priv falcongo.PrivateKey
	copy(priv[:], privateKey)
	var pub falcongo.PublicKey // Empty, not used for signing
	kp := falcongo.KeyPair{PublicKey: pub, PrivateKey: priv}
	sig, err := kp.Sign(message)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

type unsaltedTestDSA struct{}

func (unsaltedTestDSA) KeyType() string          { return "test.unsalted.v1" }
func (unsaltedTestDSA) RoutingFamily() string    { return "unsalted" }
func (unsaltedTestDSA) Version() int             { return 1 }
func (unsaltedTestDSA) CryptoSignatureSize() int { return 1 }
func (unsaltedTestDSA) MnemonicScheme() string   { return "bip39" }
func (unsaltedTestDSA) MnemonicWordCount() int   { return 24 }
func (unsaltedTestDSA) DisplayColor() string     { return "" }
func (unsaltedTestDSA) DeriveLsig(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("DeriveLsig should not be called without SaltedDeriver")
}

type boundedGeneratorTestDSA struct{ testFalcon1024V1 }

func (*boundedGeneratorTestDSA) KeyType() string       { return "test.generator-bounded.v1" }
func (*boundedGeneratorTestDSA) RoutingFamily() string { return "generator-bounded" }
func (*boundedGeneratorTestDSA) BaseKeyType() string   { return "aplane.falcon1024.v1" }
func (*boundedGeneratorTestDSA) BuildBoundedAuthorizationMetadata(_ []byte, _ map[string]string, bytecode []byte) (*boundedmeta.Metadata, error) {
	return &boundedmeta.Metadata{
		Contract:               boundedmeta.ContractV1,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{family.MaxSignatureSize}},
		ArgumentLayout:         boundedmeta.BaseArgumentLayout(boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{family.MaxSignatureSize}}, false),
		SpendEffects:           []string{"pay"},
		MaxFee:                 1_000,
		AdminOperations:        []boundedmeta.AdminOperation{},
		RuntimeArgs:            []boundedmeta.RuntimeArg{},
		Layer3Policy:           boundedmeta.Layer3PolicyCustom,
	}, nil
}

// testMasterKey is a 32-byte key for testing (AES-256 requires exactly 32 bytes)
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

const testIdentityID = "test-identity"

func newTestGenerator() *LogicSigGenerator {
	ops := &testFalcon1024V1{}
	return NewLogicSigGenerator("falcon1024", map[string]LogicSigKeygenOps{
		"falcon1024":           ops,
		"aplane.falcon1024.v1": ops,
	})
}

// setupTestKeystore sets up a temp directory and configures keystore paths for testing.
func setupTestKeystore(t *testing.T) (utilkeys.Paths, func()) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	paths := utilkeys.NewPaths(".")
	genstoretest.MintFirst(t, paths, "test-identity")
	return paths, func() {
		_ = os.Chdir(oldDir)
	}
}

// TestLogicSigGeneratorKeyType verifies the key type identifier
func TestLogicSigGeneratorKeyType(t *testing.T) {
	generator := newTestGenerator()

	if generator.RoutingFamily() != "falcon1024" {
		t.Errorf("Expected key type 'falcon1024', got '%s'", generator.RoutingFamily())
	}
}

func TestDeriveSaltedLogicSigRequiresSaltedDeriver(t *testing.T) {
	_, err := deriveSaltedLogicSig(context.Background(), unsaltedTestDSA{}, []byte{1}, nil)
	if err == nil {
		t.Fatal("deriveSaltedLogicSig() error = nil, want missing SaltedDeriver error")
	}
	if !strings.Contains(err.Error(), "does not implement salted LogicSig derivation") {
		t.Fatalf("deriveSaltedLogicSig() error = %v, want missing SaltedDeriver error", err)
	}
}

// TestGenerateFromSeed verifies deterministic Falcon key generation from seed
func TestGenerateFromSeed(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	// Create a deterministic 64-byte seed (Falcon requirement)
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Generate first key
	result1, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed failed: %v", err)
	}

	// Verify address is not empty
	if result1.Address == "" {
		t.Error("Generated address should not be empty")
	}

	// Verify public key is not empty
	if result1.PublicKeyHex == "" {
		t.Error("Generated public key should not be empty")
	}

	// Verify no mnemonic (seed-based generation)
	if result1.Mnemonic != "" {
		t.Error("Seed-based generation should not return mnemonic")
	}

	// Verify key files were created
	if result1.KeyFiles == nil {
		t.Fatal("KeyFiles should not be nil")
	}

	if result1.KeyFiles.PrivateFile == "" {
		t.Error("Private key file should be created")
	}

	// Verify file exists
	if _, err := os.Stat(result1.KeyFiles.PrivateFile); os.IsNotExist(err) {
		t.Error("Private key file does not exist")
	}

	// Generate second key with same seed (determinism test)
	result2, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("Second GenerateFromSeed failed: %v", err)
	}

	// Verify determinism
	if result1.Address != result2.Address {
		t.Error("Same seed should produce same address")
	}

	if result1.PublicKeyHex != result2.PublicKeyHex {
		t.Error("Same seed should produce same public key")
	}
}

func TestGenerateFromSeedPersistsBoundedMetadataAfterDerivation(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()
	const keyType = "test.generator-bounded.v1"
	dsa := &boundedGeneratorTestDSA{}
	logicsigdsa.Register(dsa)
	ops := &testFalcon1024V1{}
	generator := NewLogicSigGenerator("generator-bounded", map[string]LogicSigKeygenOps{keyType: ops})
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	result, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), keyType, nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed() error = %v", err)
	}
	keyJSON, err := apkeys.ReadDecryptedKeyJSONWithKeyring(result.KeyFiles.PrivateFile, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("ReadDecryptedKeyJSONWithKeyring() error = %v", err)
	}
	defer crypto.ZeroBytes(keyJSON)
	payload, err := apkeys.ParsePayload(keyJSON)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	defer payload.ZeroSecrets()
	if payload.SigningMetadataVersion != apkeys.BoundedSigningMetadataVersion || payload.BoundedAuthorization == nil {
		t.Fatalf("bounded authorization metadata = %#v", payload.BoundedAuthorization)
	}
	if got, want := payload.BoundedAuthorization.ArgumentBytesForPath(boundedmeta.PathSpend), family.MaxSignatureSize; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
}

// TestGenerateFromSeedWithEncryption verifies encrypted key storage
func TestGenerateFromSeedWithEncryption(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()
	seed := make([]byte, 64)
	masterKey := testMasterKey

	result, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, masterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed with encryption failed: %v", err)
	}

	// Read the private key file
	data, err := os.ReadFile(result.KeyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}

	// Verify it's encrypted
	if !crypto.IsEncrypted(data) {
		t.Error("Private key file should be encrypted")
	}

	// Verify we can decrypt it (using master key encryption)
	_, err = cryptotest.Keyring(t, masterKey).Open(data, mustCredentialContextForTest(t, result.KeyFiles.PrivateFile))
	if err != nil {
		t.Errorf("Failed to decrypt private key file: %v", err)
	}
}

// TestGenerateFromSeedDifferentSizes verifies Falcon accepts various seed sizes
// Note: Falcon library doesn't strictly validate seed size
func TestGenerateFromSeedDifferentSizes(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	// Test with 64-byte seed (standard)
	seed64 := make([]byte, 64)
	for i := range seed64 {
		seed64[i] = byte(i)
	}

	result, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed64, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Errorf("64-byte seed should work: %v", err)
	}

	if result != nil && result.Address == "" {
		t.Error("Should generate valid address")
	}
}

// TestGenerateFromMnemonic verifies Falcon key generation from BIP-39 mnemonic
func registerTestMnemonicHandler() {
	mnemonicreg.Register(bip39impl.NewHandler("falcon1024", family.MnemonicWordCount))
}

func TestGenerateFromMnemonic(t *testing.T) {
	registerTestMnemonicHandler()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	// Use a known BIP-39 test mnemonic (24 words)
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	result, err := generator.GenerateFromMnemonic(context.Background(), paths, testIdentityID, testMnemonic, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromMnemonic failed: %v", err)
	}

	// Verify address is generated
	if result.Address == "" {
		t.Error("Address should not be empty")
	}

	// Verify public key is generated
	if result.PublicKeyHex == "" {
		t.Error("Public key should not be empty")
	}

	// Verify mnemonic is preserved
	if result.Mnemonic != testMnemonic {
		t.Error("Mnemonic should be preserved in result")
	}

	// Verify key files were created
	if result.KeyFiles == nil || result.KeyFiles.PrivateFile == "" {
		t.Error("Private key file should be created")
	}

	// Verify determinism: same mnemonic should produce same address
	result2, err := generator.GenerateFromMnemonic(context.Background(), paths, testIdentityID, testMnemonic, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("Second GenerateFromMnemonic failed: %v", err)
	}

	if result.Address != result2.Address {
		t.Error("Same mnemonic should produce same address")
	}
}

// TestGenerateFromMnemonicInvalid verifies error handling for invalid mnemonics
func TestGenerateFromMnemonicInvalid(t *testing.T) {
	registerTestMnemonicHandler()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	tests := []struct {
		name     string
		mnemonic string
	}{
		{
			name:     "empty mnemonic",
			mnemonic: "",
		},
		{
			name:     "too few words",
			mnemonic: "abandon abandon abandon",
		},
		{
			name:     "invalid word",
			mnemonic: "invalid notaword fake abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generator.GenerateFromMnemonic(context.Background(), paths, testIdentityID, tt.mnemonic, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
			if err == nil {
				t.Error("Expected error for invalid mnemonic")
			}
		})
	}
}

// TestGenerateRandom verifies random Falcon key generation
func TestGenerateRandom(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	result, err := generator.GenerateRandom(context.Background(), paths, testIdentityID, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Verify address is generated
	if result.Address == "" {
		t.Error("Address should not be empty")
	}

	// Verify Algorand address format (58 characters)
	if len(result.Address) != 58 {
		t.Errorf("Algorand address should be 58 characters, got %d", len(result.Address))
	}

	// Verify public key is generated (Falcon-1024 public key is 1793 bytes = 3586 hex chars)
	if result.PublicKeyHex == "" {
		t.Error("Public key should not be empty")
	}

	// Verify mnemonic is generated (24 words for 256-bit entropy)
	if result.Mnemonic == "" {
		t.Error("Mnemonic should be generated")
	}

	words := strings.Fields(result.Mnemonic)
	if len(words) != 24 {
		t.Errorf("Expected 24 words in mnemonic, got %d", len(words))
	}

	// Verify key files were created
	if result.KeyFiles == nil || result.KeyFiles.PrivateFile == "" {
		t.Error("Private key file should be created")
	}

	// Verify file exists with correct permissions
	info, err := os.Stat(result.KeyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("Private key file does not exist: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Private key file should have 0600 permissions, got %o", mode)
	}
}

// TestGenerateRandomUniqueness verifies each random generation is unique
func TestGenerateRandomUniqueness(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	addresses := make(map[string]bool)
	mnemonics := make(map[string]bool)
	iterations := 5

	for i := 0; i < iterations; i++ {
		result, err := generator.GenerateRandom(context.Background(), paths, testIdentityID, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
		if err != nil {
			t.Fatalf("GenerateRandom iteration %d failed: %v", i, err)
		}

		// Check for duplicate addresses
		if addresses[result.Address] {
			t.Errorf("Duplicate address generated at iteration %d", i)
		}
		addresses[result.Address] = true

		// Check for duplicate mnemonics
		if mnemonics[result.Mnemonic] {
			t.Errorf("Duplicate mnemonic generated at iteration %d", i)
		}
		mnemonics[result.Mnemonic] = true
	}

	if len(addresses) != iterations {
		t.Errorf("Expected %d unique addresses, got %d", iterations, len(addresses))
	}
}

// TestPublicKeyFormat verifies Falcon public key hex format
func TestPublicKeyFormat(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()
	seed := make([]byte, 64)

	result, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed failed: %v", err)
	}

	// Verify public key is valid hex
	_, err = hex.DecodeString(result.PublicKeyHex)
	if err != nil {
		t.Errorf("Public key should be valid hex: %v", err)
	}

	// Falcon-1024 public key is 1793 bytes = 3586 hex characters
	expectedLen := 1793 * 2
	if len(result.PublicKeyHex) != expectedLen {
		t.Errorf("Public key hex should be %d characters, got %d", expectedLen, len(result.PublicKeyHex))
	}
}

// TestKeysDirectoryCreation verifies automatic identities/default/keys/ directory creation
func TestKeysDirectoryCreation(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	// Ensure identities directory doesn't exist
	_ = os.RemoveAll("identities")

	generator := newTestGenerator()
	seed := make([]byte, 64)

	// An uninitialized store (no generation) refuses key generation.
	if _, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil); err == nil {
		t.Fatal("GenerateFromSeed succeeded on an uninitialized store")
	}
}

// TestKeyFileNaming verifies key file naming convention
func TestKeyFileNaming(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()
	seed := make([]byte, 64)

	result, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed failed: %v", err)
	}

	// Verify file naming inside the active generation.
	active, err := genstore.ResolveActive(paths, testIdentityID)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	expectedFile := filepath.Join(active.KeysDir(), result.Address+".key")
	if result.KeyFiles.PrivateFile != expectedFile {
		t.Errorf("Private key file = %q, want %q", result.KeyFiles.PrivateFile, expectedFile)
	}
}

// TestLSigBytecodeGeneration verifies LogicSig bytecode is generated
func TestLSigBytecodeGeneration(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()
	seed := make([]byte, 64)

	result, err := generator.GenerateFromSeed(context.Background(), paths, testIdentityID, seed, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed failed: %v", err)
	}

	// Read the key file
	data, err := os.ReadFile(result.KeyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	decrypted, err := cryptotest.Keyring(t, testMasterKey).Open(data, mustCredentialContextForTest(t, result.KeyFiles.PrivateFile))
	if err != nil {
		t.Fatalf("Failed to decrypt key file: %v", err)
	}
	defer crypto.ZeroBytes(decrypted)

	// Parse as JSON
	var keyData map[string]interface{}
	if err := json.Unmarshal(decrypted, &keyData); err != nil {
		t.Fatalf("Key file is not valid JSON: %v", err)
	}

	// Verify lsig_bytecode field exists
	lsigHex, ok := keyData["lsig_bytecode"].(string)
	if !ok || lsigHex == "" {
		t.Error("Key file should contain lsig_bytecode field")
	}

	// Verify it's valid hex
	lsigBytes, err := hex.DecodeString(lsigHex)
	if err != nil {
		t.Errorf("lsig_bytecode should be valid hex: %v", err)
	}

	// Verify it's non-empty (LogicSig program)
	if len(lsigBytes) == 0 {
		t.Error("LogicSig bytecode should not be empty")
	}
}

// TestMnemonicRoundTrip verifies mnemonic can regenerate the same keys
func TestMnemonicRoundTrip(t *testing.T) {
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()

	generator := newTestGenerator()

	// Generate random key with mnemonic
	result1, err := generator.GenerateRandom(context.Background(), paths, testIdentityID, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Regenerate from mnemonic
	result2, err := generator.GenerateFromMnemonic(context.Background(), paths, testIdentityID, result1.Mnemonic, cryptotest.Keyring(t, testMasterKey), "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromMnemonic failed: %v", err)
	}

	// Verify same address
	if result1.Address != result2.Address {
		t.Error("Mnemonic should regenerate same address")
	}

	// Verify same public key
	if result1.PublicKeyHex != result2.PublicKeyHex {
		t.Error("Mnemonic should regenerate same public key")
	}

	data, err := os.ReadFile(result2.KeyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	decrypted, err := cryptotest.Keyring(t, testMasterKey).Open(data, mustCredentialContextForTest(t, result2.KeyFiles.PrivateFile))
	if err != nil {
		t.Fatalf("decryptWithTermKey() error = %v", err)
	}
	defer crypto.ZeroBytes(decrypted)
	payload, err := apkeys.ParsePayload(decrypted)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	defer payload.ZeroSecrets()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(decrypted, &fields); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, removed := range []string{"entropy", "derivation", "address", "template", "params", "bytecode_hex"} {
		if _, exists := fields[removed]; exists {
			t.Fatalf("mnemonic-backed key persisted removed field %q", removed)
		}
	}
}

// mustCredentialContextForTest derives the context the store binds into a
// managed credential's envelope, so a test opening one directly agrees with
// the writer.
func mustCredentialContextForTest(t *testing.T, path string) crypto.ObjectContext {
	t.Helper()
	ctx, err := apkeys.CredentialContextForFile(path)
	if err != nil {
		t.Fatalf("CredentialContextForFile(%q): %v", path, err)
	}
	return ctx
}
