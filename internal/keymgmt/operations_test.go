// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"context"
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	"github.com/aplane-algo/aplane/internal/storepaths"
	falcon1024attested "github.com/aplane-algo/aplane/lsig/falcon1024_attested"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

func init() {
	lsigsignerreg.RegisterSigner()
	ed25519.RegisterSigner()
}

func TestGenerateKeyRejectsMissingAndInvalidType(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())

	_, err := GenerateKey(paths, "test-identity", "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "key type must be specified") {
		t.Fatalf("GenerateKey(empty) error = %v, want missing key type", err)
	}

	_, err = GenerateKey(paths, "test-identity", "not-a-real-key-type", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid key type") {
		t.Fatalf("GenerateKey(invalid) error = %v, want invalid key type", err)
	}
}

func TestImportKeyRejectsInvalidType(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())

	_, err := ImportKey(paths, "test-identity", "not-a-real-key-type", "mnemonic words here", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid key type") {
		t.Fatalf("ImportKey(invalid) error = %v, want invalid key type", err)
	}
}

func TestSupportsMnemonicImport(t *testing.T) {
	tests := []struct {
		keyType string
		want    bool
	}{
		{keyType: "ed25519", want: true},
		{keyType: "aplane.falcon1024.v1", want: true},
		{keyType: falcon1024attested.KeyTypeV1, want: false},
		{keyType: "aplane.ecdsak1.v1", want: false},
		{keyType: "aplane.falcon1024_ed25519.v1", want: false},
		{keyType: "aplane.falcon1024-whitelist.v1", want: false},
		{keyType: "", want: false},
	}

	for _, tt := range tests {
		if got := SupportsMnemonicImport(tt.keyType); got != tt.want {
			t.Fatalf("SupportsMnemonicImport(%q) = %v, want %v", tt.keyType, got, tt.want)
		}
	}
}

func TestImportKeyRejectsValidButNonImportableType(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())

	_, err := ImportKeyWithActivatedContext(context.Background(), paths, "test-identity", "aplane.ecdsak1.v1", "mnemonic words here", nil, nil, []string{"aplane.ecdsak1.v1"})
	if err == nil || !strings.Contains(err.Error(), "mnemonic import not supported") {
		t.Fatalf("ImportKeyWithActivatedContext(aplane.ecdsak1.v1) error = %v, want mnemonic import unsupported", err)
	}
}

func TestImportKeyRestoresCanonicalPathWhenExistingKeyIsNonCanonical(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("0123456789abcdef0123456789abcdef")

	first, err := GenerateKey(paths, "test-identity", "ed25519", masterKey, nil)
	if err != nil {
		t.Fatalf("GenerateKey(first) error = %v", err)
	}
	duplicatePath := filepath.Join(paths.KeysDir("test-identity"), "duplicate.key")
	if err := os.Rename(first.KeyFile, duplicatePath); err != nil {
		t.Fatalf("Rename(%q, %q) error = %v", first.KeyFile, duplicatePath, err)
	}

	second, err := ImportKey(paths, "test-identity", "ed25519", first.Mnemonic, masterKey, nil)
	if err != nil {
		t.Fatalf("ImportKey(second) error = %v", err)
	}
	if second == nil {
		t.Fatal("ImportKey(second) result = nil, want imported key")
	}
	if second.KeyFile != first.KeyFile {
		t.Fatalf("ImportKey(second) key file = %q, want canonical path %q", second.KeyFile, first.KeyFile)
	}
	if _, statErr := os.Stat(first.KeyFile); statErr != nil {
		t.Fatalf("canonical key file stat error = %v", statErr)
	}
	if _, statErr := os.Stat(duplicatePath); statErr != nil {
		t.Fatalf("duplicate key file stat error = %v", statErr)
	}
}

func TestValidKeyTypesIncludeIdentityActivatedLibraryProvider(t *testing.T) {
	if containsKeyType(GetValidKeyTypes(), "aplane.falcon1024_ed25519.v1") {
		t.Fatal("GetValidKeyTypes() included library-only provider without activation")
	}
	if !containsKeyType(GetValidKeyTypesWithActivated([]string{"aplane.falcon1024_ed25519.v1"}), "aplane.falcon1024_ed25519.v1") {
		t.Fatal("GetValidKeyTypesWithActivated() did not include activated library provider")
	}
	if IsValidKeyType("aplane.falcon1024_ed25519.v1") {
		t.Fatal("IsValidKeyType() accepted library-only provider without activation")
	}
	if !IsValidKeyTypeWithActivated("aplane.falcon1024_ed25519.v1", []string{"aplane.falcon1024_ed25519.v1"}) {
		t.Fatal("IsValidKeyTypeWithActivated() rejected activated library provider")
	}
}

func TestValidKeyTypesIncludeIdentityActivatedYAMLComposedProvider(t *testing.T) {
	keyType := "keymgmt-composed-activated-v1"
	logicsigdsa.RegisterIfAbsent(keymgmtTestDSAProvider{keyType: keyType})

	if containsKeyType(GetValidKeyTypes(), keyType) {
		t.Fatal("GetValidKeyTypes() included non-default provider without identity state")
	}
	if !containsKeyType(GetValidKeyTypesWithActivated([]string{keyType}), keyType) {
		t.Fatal("GetValidKeyTypesWithActivated() did not include identity-enabled composed provider")
	}
	if IsValidKeyType(keyType) {
		t.Fatal("IsValidKeyType() accepted composed provider without identity state")
	}
	if !IsValidKeyTypeWithActivated(keyType, []string{keyType}) {
		t.Fatal("IsValidKeyTypeWithActivated() rejected identity-enabled composed provider")
	}
}

func TestValidKeyTypesIncludeAttestorComponentKey(t *testing.T) {
	if !containsKeyType(GetValidKeyTypes(), keytypes.AttestorComponentEd25519V1) {
		t.Fatalf("GetValidKeyTypes() missing %s", keytypes.AttestorComponentEd25519V1)
	}
	if !IsValidKeyType(keytypes.AttestorComponentEd25519V1) {
		t.Fatalf("IsValidKeyType() rejected %s", keytypes.AttestorComponentEd25519V1)
	}
}

func TestValidKeyTypesIncludeFalcon1024AttestedKey(t *testing.T) {
	if !containsKeyType(GetValidKeyTypes(), falcon1024attested.KeyTypeV1) {
		t.Fatalf("GetValidKeyTypes() missing %s", falcon1024attested.KeyTypeV1)
	}
	if !IsValidKeyType(falcon1024attested.KeyTypeV1) {
		t.Fatalf("IsValidKeyType() rejected %s", falcon1024attested.KeyTypeV1)
	}
}

func TestGenerateKeyFalcon1024AttestedRequiresAttestorPublicKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("0123456789abcdef0123456789abcdef")

	_, err := GenerateKey(paths, "test-identity", falcon1024attested.KeyTypeV1, masterKey, nil)
	if err == nil || !strings.Contains(err.Error(), "missing required parameter: attestor_public_key") {
		t.Fatalf("GenerateKey(attested missing params) error = %v, want missing attestor_public_key", err)
	}
}

func TestGenerateKeyFalcon1024AttestedPersistsSigningMetadata(t *testing.T) {
	configureAttestedCompileMock(t)

	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	attestorPublicKey := strings.Repeat("ab", stded25519.PublicKeySize)

	result, err := GenerateKey(paths, "test-identity", falcon1024attested.KeyTypeV1, masterKey, map[string]string{
		falcon1024attested.ParamAttestorPublicKey: attestorPublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateKey(attested) error = %v", err)
	}
	if result.KeyType != falcon1024attested.KeyTypeV1 {
		t.Fatalf("KeyType = %q, want %s", result.KeyType, falcon1024attested.KeyTypeV1)
	}
	if result.Address == "" {
		t.Fatal("Address is empty")
	}
	if result.IsComponentKey {
		t.Fatalf("attested account marked as component: %#v", result)
	}

	decrypted, err := apkeys.ReadDecryptedKeyJSONWithMasterKey(result.KeyFile, masterKey)
	if err != nil {
		t.Fatalf("ReadDecryptedKeyJSONWithMasterKey() error = %v", err)
	}
	defer crypto.ZeroBytes(decrypted)

	var keyPair apkeys.KeyPair
	if err := json.Unmarshal(decrypted, &keyPair); err != nil {
		t.Fatalf("json.Unmarshal(KeyPair) error = %v", err)
	}
	if keyPair.Category != apkeys.CategoryDSALsig {
		t.Fatalf("Category = %q, want %s", keyPair.Category, apkeys.CategoryDSALsig)
	}
	if keyPair.KeyType != falcon1024attested.KeyTypeV1 {
		t.Fatalf("stored KeyType = %q, want %s", keyPair.KeyType, falcon1024attested.KeyTypeV1)
	}
	if keyPair.BaseKeyType != falcon1024attested.BaseKeyType {
		t.Fatalf("BaseKeyType = %q, want %s", keyPair.BaseKeyType, falcon1024attested.BaseKeyType)
	}
	if keyPair.Params[falcon1024attested.ParamAttestorPublicKey] != attestorPublicKey {
		t.Fatalf("attestor public key param = %q, want %q", keyPair.Params[falcon1024attested.ParamAttestorPublicKey], attestorPublicKey)
	}
	if keyPair.LsigBytecodeHex == "" {
		t.Fatal("LsigBytecodeHex is empty")
	}
	if keyPair.SaltCounter == nil {
		t.Fatal("SaltCounter is nil")
	}
	if keyPair.SigningMetadataVersion != apkeys.CurrentSigningMetadataVersion {
		t.Fatalf("SigningMetadataVersion = %d, want %d", keyPair.SigningMetadataVersion, apkeys.CurrentSigningMetadataVersion)
	}
	if keyPair.TemplateFingerprint == "" {
		t.Fatal("TemplateFingerprint is empty")
	}
}

func TestGenerateKeyAttestorComponent(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := []byte("0123456789abcdef0123456789abcdef")

	result, err := GenerateKey(paths, "test-identity", keytypes.AttestorComponentEd25519V1, masterKey, nil)
	if err != nil {
		t.Fatalf("GenerateKey(component) error = %v", err)
	}
	if !result.IsComponentKey {
		t.Fatal("IsComponentKey = false, want true")
	}
	if result.IsSpendingAccount == nil || *result.IsSpendingAccount {
		t.Fatalf("IsSpendingAccount = %#v, want false pointer", result.IsSpendingAccount)
	}
	if result.PublicKeyHex == "" {
		t.Fatal("PublicKeyHex is empty")
	}
	if result.Address != result.PublicKeyHex {
		t.Fatalf("Address = %q, want public key hex %q", result.Address, result.PublicKeyHex)
	}
	if result.Mnemonic != "" {
		t.Fatalf("Mnemonic = %q, want empty", result.Mnemonic)
	}
}

func TestDetectKeyInfoFromFileWithMasterKeyRejectsPlaintext(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "plain.key")
	content := []byte(`{"key_type":"aplane.timed-whitelist.v1","parameters":{"recipients":"ADDR"}}`)
	if err := os.WriteFile(keyFile, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := DetectKeyInfoFromFileWithMasterKey(keyFile, nil)
	if err == nil {
		t.Fatal("DetectKeyInfoFromFileWithMasterKey() error = nil, want plaintext rejection")
	}
	if !strings.Contains(err.Error(), "must be encrypted") {
		t.Fatalf("DetectKeyInfoFromFileWithMasterKey() error = %v, want encrypted rejection", err)
	}
}

func containsKeyType(items []string, keyType string) bool {
	for _, item := range items {
		if item == keyType {
			return true
		}
	}
	return false
}

func configureAttestedCompileMock(t *testing.T) {
	t.Helper()
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, attestedCompileMockTransport{})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	lsigprovider.ConfigureAlgodClient(client)
}

type attestedCompileMockTransport struct{}

func (attestedCompileMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
	bytecode := compiledAttestedPushbytesSaltBytecode(0)
	body := `{"result":"` + base64.StdEncoding.EncodeToString(bytecode) + `","hash":"TESTHASH"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func compiledAttestedPushbytesSaltBytecode(counter byte) []byte {
	marker := lsigsalt.PushbytesSaltMarker(counter)
	bytecode := []byte{0x0c, 0x80, byte(len(marker))}
	bytecode = append(bytecode, marker...)
	bytecode = append(bytecode, 0x48, 0x81, 0x01)
	return bytecode
}

func TestDetectKeyInfoFromFileWithMasterKeyEncrypted(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encrypted.key")
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte(`{"key_type":"aplane.falcon1024.v1","params":{"network":"testnet"}}`)
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	info, err := DetectKeyInfoFromFileWithMasterKey(keyFile, masterKey)
	if err != nil {
		t.Fatalf("DetectKeyInfoFromFileWithMasterKey() error = %v", err)
	}
	if info.Type != "aplane.falcon1024.v1" {
		t.Fatalf("Type = %q, want aplane.falcon1024.v1", info.Type)
	}
	if info.Parameters["network"] != "testnet" {
		t.Fatalf("network = %q, want testnet", info.Parameters["network"])
	}
}

func TestDeleteKey(t *testing.T) {
	// Set up a key file in the identity-scoped keys directory
	tmpDir := t.TempDir()
	identityID := "default"
	keysDir := filepath.Join(tmpDir, "identities", identityID, "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(keysDir, "TESTADDR.key")
	if err := os.WriteFile(keyFile, []byte(`{"key_type":"ed25519"}`), 0600); err != nil {
		t.Fatal(err)
	}

	paths := storepaths.NewPaths(tmpDir)
	result, err := DeleteKey("TESTADDR", keyFile, paths.DeletedKeysDir(identityID))
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	// Key file should no longer exist at original location
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Error("original key file should be deleted")
	}

	// Should exist in the identity-local deleted keys directory
	if _, err := os.Stat(result.DeletedPath); err != nil {
		t.Errorf("key should exist at deleted path %s: %v", result.DeletedPath, err)
	}

	// Verify deleted path structure.
	expectedDir := paths.DeletedKeysDir(identityID)
	if filepath.Dir(result.DeletedPath) != expectedDir {
		t.Errorf("deleted dir = %q, want %q", filepath.Dir(result.DeletedPath), expectedDir)
	}
}

func TestDeleteKey_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "identities", "default", "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatal(err)
	}

	paths := storepaths.NewPaths(tmpDir)
	_, err := DeleteKey("NOADDR", filepath.Join(keysDir, "NOADDR.key"), paths.DeletedKeysDir("default"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDeleteKey_RenameFailure(t *testing.T) {
	tmpDir := t.TempDir()
	identityID := "default"
	keysDir := filepath.Join(tmpDir, "identities", identityID, "keys")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(keysDir, "TESTADDR.key")
	if err := os.WriteFile(keyFile, []byte(`{"key_type":"ed25519"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	paths := storepaths.NewPaths(tmpDir)
	deletedDir := paths.DeletedKeysDir(identityID)
	if err := os.MkdirAll(deletedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(deletedDir, "TESTADDR.key")
	if err := os.MkdirAll(destPath, 0o750); err != nil {
		t.Fatal(err)
	}

	_, err := DeleteKey("TESTADDR", keyFile, paths.DeletedKeysDir(identityID))
	if err == nil || !strings.Contains(err.Error(), "failed to move key file") {
		t.Fatalf("DeleteKey(rename failure) error = %v, want move failure", err)
	}
}

func TestDetectKeyInfoFromFileWithMasterKeyMissingFile(t *testing.T) {
	_, err := DetectKeyInfoFromFileWithMasterKey("/nonexistent/path.key", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDetectKeyInfoFromFileWithMasterKeyWrongMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encrypted.key")
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	wrongKey := []byte("fedcba9876543210fedcba9876543210")
	plaintext := []byte(`{"key_type":"aplane.timed-whitelist.v1","parameters":{"recipients":"ADDR"}}`)
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = DetectKeyInfoFromFileWithMasterKey(keyFile, wrongKey)
	if err == nil {
		t.Fatal("expected decrypt error, got nil")
	}
}

func TestDetectKeyInfoFromFileWithMasterKeyInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "invalid.key")
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	encrypted, err := crypto.EncryptWithMasterKey([]byte(`{invalid`), masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = DetectKeyInfoFromFileWithMasterKey(keyFile, masterKey)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestGetDisplayTEALWithMasterKeyEncrypted(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "display.key")
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte(`{"teal_source":"#pragma version 8\nint 1"}`)
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	teal, err := GetDisplayTEALWithMasterKey(keyFile, masterKey)
	if err != nil {
		t.Fatalf("GetDisplayTEALWithMasterKey() error = %v", err)
	}
	if teal != "#pragma version 8\nint 1" {
		t.Fatalf("TEAL = %q, want stored source", teal)
	}
}

func TestGetDisplayTEALWithMasterKeyWrongMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "display.key")
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	wrongKey := []byte("fedcba9876543210fedcba9876543210")
	plaintext := []byte(`{"teal_source":"#pragma version 8\nint 1"}`)
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = GetDisplayTEALWithMasterKey(keyFile, wrongKey)
	if err == nil {
		t.Fatal("expected decrypt error, got nil")
	}
}

func TestGetDisplayTEALWithMasterKeyInvalidJSON(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "display.key")
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	encrypted, err := crypto.EncryptWithMasterKey([]byte(`{invalid`), masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = GetDisplayTEALWithMasterKey(keyFile, masterKey)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestParseKeyFileInfoPrefersParametersAndFallsBackToParams(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantType   string
		wantParamK string
		wantParamV string
	}{
		{
			name:       "uses parameters when present",
			payload:    `{"key_type":"aplane.timed-whitelist.v1","parameters":{"recipients":"ADDR1"}}`,
			wantType:   "aplane.timed-whitelist.v1",
			wantParamK: "recipients",
			wantParamV: "ADDR1",
		},
		{
			name:       "allows duplicate aliases when equal",
			payload:    `{"key_type":"aplane.timed-whitelist.v1","parameters":{"recipients":"ADDR1"},"params":{"recipients":"ADDR1"}}`,
			wantType:   "aplane.timed-whitelist.v1",
			wantParamK: "recipients",
			wantParamV: "ADDR1",
		},
		{
			name:       "falls back to params",
			payload:    `{"key_type":"aplane.falcon1024.v1","params":{"network":"testnet"}}`,
			wantType:   "aplane.falcon1024.v1",
			wantParamK: "network",
			wantParamV: "testnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseKeyFileInfo([]byte(tt.payload))
			if err != nil {
				t.Fatalf("parseKeyFileInfo() error = %v", err)
			}
			if info.Type != tt.wantType {
				t.Fatalf("Type = %q, want %q", info.Type, tt.wantType)
			}
			if info.Parameters[tt.wantParamK] != tt.wantParamV {
				t.Fatalf("Parameters[%q] = %q, want %q", tt.wantParamK, info.Parameters[tt.wantParamK], tt.wantParamV)
			}
		})
	}
}

func TestParseKeyFileInfoIncludesPublicKey(t *testing.T) {
	info, err := parseKeyFileInfo([]byte(`{"key_type":"aplane.attestor-ed25519.v1","public_key":"aabbccdd"}`))
	if err != nil {
		t.Fatalf("parseKeyFileInfo() error = %v", err)
	}
	if info.PublicKeyHex != "aabbccdd" {
		t.Fatalf("PublicKeyHex = %q, want aabbccdd", info.PublicKeyHex)
	}
}

func TestParseKeyFileInfoRejectsConflictingParameterAliases(t *testing.T) {
	_, err := parseKeyFileInfo([]byte(`{"key_type":"aplane.timed-whitelist.v1","parameters":{"recipients":"ADDR1"},"params":{"recipients":"ADDR2"}}`))
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("error = %q, want conflicting fields", err.Error())
	}
}

func TestParseKeyFileInfoMissingKeyType(t *testing.T) {
	_, err := parseKeyFileInfo([]byte(`{"parameters":{"recipient":"ADDR"}}`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing required 'key_type' field") {
		t.Fatalf("error = %q, want missing key_type", err.Error())
	}
}

func TestParseKeyFileInfoInvalidJSON(t *testing.T) {
	_, err := parseKeyFileInfo([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestParseDisplayTEALMissingFieldReturnsEmpty(t *testing.T) {
	teal, err := parseDisplayTEAL([]byte(`{"key_type":"aplane.timed-whitelist.v1"}`))
	if err != nil {
		t.Fatalf("parseDisplayTEAL() error = %v", err)
	}
	if teal != "" {
		t.Fatalf("TEAL = %q, want empty", teal)
	}
}

func TestParseDisplayTEALInvalidJSON(t *testing.T) {
	_, err := parseDisplayTEAL([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

type keymgmtTestDSAProvider struct {
	keyType string
}

func (p keymgmtTestDSAProvider) KeyType() string { return p.keyType }
func (p keymgmtTestDSAProvider) Family() string {
	return strings.TrimSuffix(p.keyType, "-v1")
}
func (p keymgmtTestDSAProvider) Version() int                                { return 1 }
func (p keymgmtTestDSAProvider) Category() string                            { return lsigprovider.CategoryDSALsig }
func (p keymgmtTestDSAProvider) DisplayName() string                         { return "Keymgmt Test DSA" }
func (p keymgmtTestDSAProvider) Description() string                         { return "Test provider" }
func (p keymgmtTestDSAProvider) DisplayColor() string                        { return "" }
func (p keymgmtTestDSAProvider) CreationParams() []lsigprovider.ParameterDef { return nil }
func (p keymgmtTestDSAProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p keymgmtTestDSAProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }
func (p keymgmtTestDSAProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (p keymgmtTestDSAProvider) CryptoSignatureSize() int { return 0 }
func (p keymgmtTestDSAProvider) MnemonicScheme() string   { return "bip39" }
func (p keymgmtTestDSAProvider) MnemonicWordCount() int   { return 24 }
func (p keymgmtTestDSAProvider) DeriveLsig(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", nil
}
