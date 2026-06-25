// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/merklewhitelist"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestMain(m *testing.M) {
	addressderive.RegisterEd25519()
	os.Exit(m.Run())
}

type scanSizeTestDSA struct {
	keyType string
	sigSize int
}

func (p scanSizeTestDSA) KeyType() string { return p.keyType }

func (p scanSizeTestDSA) Family() string { return "scan-size-test" }

func (p scanSizeTestDSA) Version() int { return 1 }

func (p scanSizeTestDSA) Category() string { return lsigprovider.CategoryDSALsig }

func (p scanSizeTestDSA) DisplayName() string { return "Scan Size Test" }

func (p scanSizeTestDSA) Description() string { return "test-only provider" }

func (p scanSizeTestDSA) DisplayColor() string { return "" }

func (p scanSizeTestDSA) CreationParams() []lsigprovider.ParameterDef { return nil }

func (p scanSizeTestDSA) ValidateCreationParams(map[string]string) error { return nil }

func (p scanSizeTestDSA) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }

func (p scanSizeTestDSA) BuildArgs(signature []byte, _ map[string][]byte) ([][]byte, error) {
	return [][]byte{signature}, nil
}

func (p scanSizeTestDSA) CryptoSignatureSize() int { return p.sigSize }

func (p scanSizeTestDSA) MnemonicScheme() string { return "" }

func (p scanSizeTestDSA) MnemonicWordCount() int { return 0 }

func (p scanSizeTestDSA) DeriveLsig(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("scan-size test provider does not derive LogicSigs")
}

// testMasterKey generates a 32-byte AES-256 key for test encryption.
func testMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate test master key: %v", err)
	}
	return key
}

// testEd25519Key generates a random Ed25519 key pair and returns the JSON data and address.
func testEd25519Key(t *testing.T) (keyJSON []byte, address string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}
	var pk [32]byte
	copy(pk[:], pub)
	address = types.Address(pk).String()

	data := map[string]interface{}{
		"format_version": CurrentKeyFormatVersion,
		"category":       CategoryEd25519,
		"key_type":       "ed25519",
		"public_key":     hex.EncodeToString(pub),
		"private_key":    hex.EncodeToString(priv),
	}
	keyJSON, err = json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	return keyJSON, address
}

// writeKeyFile writes key JSON to the identity-scoped keys directory, optionally encrypted.
func writeKeyFile(t *testing.T, paths storepaths.Paths, identityID, address string, keyJSON, masterKey []byte) string {
	t.Helper()
	keysDir := paths.KeysDir(identityID)
	if err := fsutil.MkdirAll(keysDir); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	dataToWrite := keyJSON
	if len(masterKey) > 0 {
		encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
		if err != nil {
			t.Fatalf("Failed to encrypt key: %v", err)
		}
		dataToWrite = encrypted
	}

	filePath := filepath.Join(keysDir, address+".key")
	if err := os.WriteFile(filePath, dataToWrite, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	return filePath
}

func TestDetectKeyTypeFromData(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		want      string
		wantError bool
		errMsg    string
	}{
		{
			name: "ed25519",
			data: `{"key_type":"ed25519"}`,
			want: "ed25519",
		},
		{
			name: "aplane.falcon1024.v1",
			data: `{"key_type":"aplane.falcon1024.v1"}`,
			want: "aplane.falcon1024.v1",
		},
		{
			name: "aplane.timed-whitelist.v1",
			data: `{"key_type":"aplane.timed-whitelist.v1"}`,
			want: "aplane.timed-whitelist.v1",
		},
		{
			name:      "missing key_type",
			data:      `{"public_key":"abc"}`,
			wantError: true,
			errMsg:    "missing required 'key_type'",
		},
		{
			name:      "empty JSON",
			data:      `{}`,
			wantError: true,
			errMsg:    "missing required 'key_type'",
		},
		{
			name:      "invalid JSON",
			data:      `not json`,
			wantError: true,
			errMsg:    "failed to unmarshal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DetectKeyTypeFromData([]byte(tc.data))
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if !contains(err.Error(), tc.errMsg) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractBytecode(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string // hex of expected bytecode, or "" for nil
	}{
		{
			name: "lsig_bytecode field",
			data: `{"lsig_bytecode":"0102030405"}`,
			want: "0102030405",
		},
		{
			name: "bytecode_hex fallback",
			data: `{"bytecode_hex":"aabbcc"}`,
			want: "aabbcc",
		},
		{
			name: "conflicting bytecode aliases reject",
			data: `{"lsig_bytecode":"0102","bytecode_hex":"aabb"}`,
			want: "",
		},
		{
			name: "no bytecode fields",
			data: `{"key_type":"ed25519"}`,
			want: "",
		},
		{
			name: "invalid hex",
			data: `{"lsig_bytecode":"not-hex"}`,
			want: "",
		},
		{
			name: "invalid JSON",
			data: `not json`,
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractBytecode([]byte(tc.data))
			if tc.want == "" {
				if got != nil {
					t.Errorf("expected nil, got %x", got)
				}
				return
			}
			expected, _ := hex.DecodeString(tc.want)
			if hex.EncodeToString(got) != hex.EncodeToString(expected) {
				t.Errorf("got %x, want %x", got, expected)
			}
		})
	}
}

func TestParseKeyPayloadMetadataNormalizesAliases(t *testing.T) {
	meta, err := ParseKeyPayloadMetadata([]byte(`{
		"format_version":1,
		"category":"dsa_lsig",
		"key_type":"aplane.falcon1024.v1",
		"params":{"network":"testnet"},
		"lsig_bytecode":"0102",
		"salt_counter":5
	}`))
	if err != nil {
		t.Fatalf("ParseKeyPayloadMetadata() error = %v", err)
	}
	if !meta.HasFormatVersion || meta.FormatVersion != CurrentKeyFormatVersion {
		t.Fatalf("format version = (%d, %v), want current/present", meta.FormatVersion, meta.HasFormatVersion)
	}
	if meta.Parameters["network"] != "testnet" {
		t.Fatalf("Parameters = %#v, want normalized params", meta.Parameters)
	}
	if meta.BytecodeHex != "0102" {
		t.Fatalf("BytecodeHex = %q, want 0102", meta.BytecodeHex)
	}
	if meta.SaltCounter == nil || *meta.SaltCounter != 5 {
		t.Fatalf("SaltCounter = %v, want 5", meta.SaltCounter)
	}
}

func TestParseKeyPayloadMetadataRejectsConflictingAliases(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "parameters conflict",
			data: `{"key_type":"aplane.timed-whitelist.v1","parameters":{"recipients":"A"},"params":{"recipients":"B"}}`,
		},
		{
			name: "bytecode conflict",
			data: `{"key_type":"aplane.timed-whitelist.v1","lsig_bytecode":"0102","bytecode_hex":"0103"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKeyPayloadMetadata([]byte(tt.data))
			if !errors.Is(err, ErrIncompatibleKeyFormat) {
				t.Fatalf("ParseKeyPayloadMetadata() error = %v, want %v", err, ErrIncompatibleKeyFormat)
			}
		})
	}
}

func TestRequireLogicSigSaltCounter(t *testing.T) {
	counter, err := RequireLogicSigSaltCounter([]byte(`{"lsig_bytecode":"260101058101","salt_counter":5}`))
	if err != nil {
		t.Fatalf("RequireLogicSigSaltCounter() error = %v", err)
	}
	if counter != 5 {
		t.Fatalf("RequireLogicSigSaltCounter() = %d, want 5", counter)
	}

	if _, err := RequireLogicSigSaltCounter([]byte(`{"lsig_bytecode":"260101058101"}`)); !errors.Is(err, ErrMissingLogicSigSaltCounter) {
		t.Fatalf("RequireLogicSigSaltCounter(missing) error = %v, want %v", err, ErrMissingLogicSigSaltCounter)
	}
}

func TestLSigFileUnmarshalRequiresSaltCounter(t *testing.T) {
	var lf LSigFile
	err := json.Unmarshal([]byte(`{"category":"generic_lsig","key_type":"aplane.timed-whitelist.v1","bytecode_hex":"260101058101"}`), &lf)
	if !errors.Is(err, ErrMissingLogicSigSaltCounter) {
		t.Fatalf("json.Unmarshal(LSigFile without salt_counter) error = %v, want %v", err, ErrMissingLogicSigSaltCounter)
	}
}

func TestValidateLogicSigSaltedBytecodeRejectsOnCurveAddress(t *testing.T) {
	data := []byte(`{"lsig_bytecode":"0a810143","salt_counter":0}`)
	bytecode := ExtractBytecode(data)
	if _, err := ValidateLogicSigSaltedBytecode(data, bytecode); err == nil {
		t.Fatal("ValidateLogicSigSaltedBytecode() error = nil, want on-curve rejection")
	}
}

func TestExtractPublicKeyHex(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"present", `{"public_key":"abcdef0123"}`, "abcdef0123"},
		{"missing", `{"key_type":"ed25519"}`, ""},
		{"invalid JSON", `not json`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPublicKeyHex([]byte(tc.data))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractCreatedAt(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"present", `{"created_at":"2026-01-01T00:00:00Z"}`, "2026-01-01T00:00:00Z"},
		{"missing", `{"key_type":"ed25519"}`, ""},
		{"invalid JSON", `not json`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractCreatedAt([]byte(tc.data))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadAndDecryptFile(t *testing.T) {
	masterKey := testMasterKey(t)

	t.Run("plaintext file rejected", func(t *testing.T) {
		content := []byte(`{"key_type":"ed25519","public_key":"abc"}`)
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}

		_, err := ReadAndDecryptFile(path, nil, "test")
		if err == nil {
			t.Fatal("expected error for plaintext file")
		}
		if !contains(err.Error(), "must be encrypted") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("encrypted file", func(t *testing.T) {
		plaintext := []byte(`{"key_type":"ed25519","public_key":"abc"}`)
		encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, encrypted, 0600); err != nil {
			t.Fatal(err)
		}

		got, err := ReadAndDecryptFile(path, masterKey, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("decrypted content mismatch")
		}
	})

	t.Run("encrypted file nil master key", func(t *testing.T) {
		plaintext := []byte(`{"key_type":"ed25519"}`)
		encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, encrypted, 0600); err != nil {
			t.Fatal(err)
		}

		_, err = ReadAndDecryptFile(path, nil, "test")
		if err == nil {
			t.Fatal("expected error for encrypted file without master key")
		}
		if !contains(err.Error(), "encrypted but no master key") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := ReadAndDecryptFile("/nonexistent/path.key", masterKey, "test")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !contains(err.Error(), "failed to read") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("wrong master key", func(t *testing.T) {
		plaintext := []byte(`{"key_type":"ed25519"}`)
		encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, encrypted, 0600); err != nil {
			t.Fatal(err)
		}

		wrongKey := testMasterKey(t)
		_, err = ReadAndDecryptFile(path, wrongKey, "test")
		if err == nil {
			t.Fatal("expected error for wrong master key")
		}
		if !contains(err.Error(), "failed to decrypt") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestScanKeysDirectoryWithMasterKey(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		result, err := ScanKeysDirectoryWithMasterKey(paths, "default", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty map, got %d entries", len(result))
		}
	})

	t.Run("single encrypted ed25519 key", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())
		keyJSON, address := testEd25519Key(t)

		writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

		result, err := ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(result))
		}

		info, ok := result[address]
		if !ok {
			t.Fatalf("address %s not found in results", address)
		}
		if info.KeyType != "ed25519" {
			t.Errorf("key type = %q, want %q", info.KeyType, "ed25519")
		}
		if info.LsigSize != 0 {
			t.Errorf("lsig size = %d, want 0 for ed25519", info.LsigSize)
		}
		if info.PublicKeyHex == "" {
			t.Error("public key hex should not be empty")
		}
	})

	t.Run("filename address mismatch is skipped", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())
		keyJSON, address := testEd25519Key(t)

		firstPath := writeKeyFile(t, paths, "default", address, keyJSON, masterKey)
		encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
		if err != nil {
			t.Fatalf("EncryptWithMasterKey() error = %v", err)
		}
		duplicatePath := filepath.Join(paths.KeysDir("default"), "duplicate.key")
		if err := os.WriteFile(duplicatePath, encrypted, 0600); err != nil {
			t.Fatalf("write duplicate key file: %v", err)
		}

		report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
		if err != nil {
			t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
		}
		if len(report.Keys) != 1 {
			t.Fatalf("loaded keys = %d, want only canonical key", len(report.Keys))
		}
		if got := report.Keys[address].KeyFile; got != firstPath {
			t.Fatalf("loaded key path = %q, want canonical path %q", got, firstPath)
		}
		if len(report.Warnings) != 1 {
			t.Fatalf("warnings = %d, want 1 filename mismatch warning", len(report.Warnings))
		}
		warning := report.Warnings[0]
		if warning.Code != KeyScanWarningFilenameAddressMismatch {
			t.Fatalf("warning code = %q, want %q", warning.Code, KeyScanWarningFilenameAddressMismatch)
		}
		msg := warning.Message()
		for _, want := range []string{duplicatePath, "duplicate", address} {
			if !contains(msg, want) {
				t.Fatalf("warning message = %q, want %q", msg, want)
			}
		}
	})

	t.Run("plaintext ed25519 key skipped", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		keyJSON, address := testEd25519Key(t)

		writeKeyFile(t, paths, "default", address, keyJSON, nil)

		report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(report.Keys) != 0 {
			t.Fatalf("expected plaintext key to be skipped, got %d entries", len(report.Keys))
		}
		if len(report.Warnings) != 1 {
			t.Fatalf("warnings = %d, want 1", len(report.Warnings))
		}
		if !contains(report.Warnings[0].Err.Error(), "must be encrypted") {
			t.Fatalf("warning error = %v, want encrypted rejection", report.Warnings[0].Err)
		}
	})

	t.Run("non-key files ignored", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		keysDir := paths.KeysDir("default")
		if err := fsutil.MkdirAll(keysDir); err != nil {
			t.Fatal(err)
		}

		// Write a non-.key file
		if err := os.WriteFile(filepath.Join(keysDir, "notes.txt"), []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}

		result, err := ScanKeysDirectoryWithMasterKey(paths, "default", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected 0 entries, got %d", len(result))
		}
	})

	t.Run("subdirectories ignored", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		keysDir := paths.KeysDir("default")
		if err := fsutil.MkdirAll(keysDir); err != nil {
			t.Fatal(err)
		}

		// Create a subdirectory (should be skipped)
		if err := os.Mkdir(filepath.Join(keysDir, "subdir"), 0750); err != nil {
			t.Fatal(err)
		}

		result, err := ScanKeysDirectoryWithMasterKey(paths, "default", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected 0 entries, got %d", len(result))
		}
	})

	t.Run("corrupted file skipped", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())

		// Write a valid key
		keyJSON, address := testEd25519Key(t)
		writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

		// Write a corrupted key file
		keysDir := paths.KeysDir("default")
		if err := os.WriteFile(filepath.Join(keysDir, "BADKEY.key"), []byte("not valid data"), 0600); err != nil {
			t.Fatal(err)
		}

		result, err := ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The valid key should still be present; corrupted one skipped
		if len(result) != 1 {
			t.Errorf("expected 1 entry (corrupted skipped), got %d", len(result))
		}
	})

	t.Run("multiple keys", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())

		keyJSON1, addr1 := testEd25519Key(t)
		keyJSON2, addr2 := testEd25519Key(t)
		writeKeyFile(t, paths, "default", addr1, keyJSON1, masterKey)
		writeKeyFile(t, paths, "default", addr2, keyJSON2, masterKey)

		result, err := ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 entries, got %d", len(result))
		}
		if _, ok := result[addr1]; !ok {
			t.Errorf("address %s not found", addr1)
		}
		if _, ok := result[addr2]; !ok {
			t.Errorf("address %s not found", addr2)
		}
	})
}

func TestScanKeysDirectoryWithMasterKeyReportRecordsSaltWarnings(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	keysDir := paths.KeysDir("default")
	if err := fsutil.MkdirAll(keysDir); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(keysDir, "GENERIC.key")
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"address": "GENERIC",
		"key_type": "aplane.whitelist.v1",
		"bytecode_hex": "260101058101",
		"signing_metadata_version": 1
	}`)
	encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("loaded keys = %d, want 0", len(report.Keys))
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", report.Warnings)
	}
	warning := report.Warnings[0]
	if warning.Code != KeyScanWarningLogicSigSaltInvalid {
		t.Fatalf("warning code = %q, want %q", warning.Code, KeyScanWarningLogicSigSaltInvalid)
	}
	if !warning.IsLogicSigSaltMetadata() {
		t.Fatal("warning should be classified as LogicSig salt metadata")
	}
	if !contains(warning.Message(), "Failed to validate LogicSig salt metadata") {
		t.Fatalf("warning message = %q", warning.Message())
	}
}

func TestScanKeysDirectoryWithMasterKeyLoadsGenericUnderDerivedAddress(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	address, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"address": "` + address + `",
		"key_type": "aplane.whitelist.v1",
		"bytecode_hex": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"signing_metadata_version": 1
	}`)

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", report.Warnings)
	}
	if _, ok := report.Keys[address]; !ok {
		t.Fatalf("derived address %s not loaded", address)
	}
}

func TestScanKeysDirectoryWithMasterKeyIncludesWhitelistV2ProofBudget(t *testing.T) {
	const (
		baseKeyType = "test.scan-size-base.v1"
		baseSigSize = 123
	)
	logicsigdsa.RegisterIfAbsent(scanSizeTestDSA{keyType: baseKeyType, sigSize: baseSigSize})

	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	address, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "dsa_lsig",
		"address": "` + address + `",
		"key_type": "` + falcon1024WhitelistV2KeyType + `",
		"public_key": "01020304",
		"private_key": "05060708",
		"lsig_bytecode": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"base_key_type": "` + baseKeyType + `",
		"params": {
			"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
		},
		"signing_metadata_version": 1
	}`)

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", report.Warnings)
	}
	info, ok := report.Keys[address]
	if !ok {
		t.Fatalf("derived address %s not loaded", address)
	}
	want := len(bytecode) + baseSigSize + merklewhitelist.ProofSize
	if info.LsigSize != want {
		t.Fatalf("LsigSize = %d, want %d", info.LsigSize, want)
	}
}

func TestSignerGeneratedDSAArgSizeIncludesCorridorProofBudget(t *testing.T) {
	if got := signerGeneratedDSAArgSizeForKey(keytypes.CorridorV1); got != merklewhitelist.ProofSize {
		t.Fatalf("signerGeneratedDSAArgSizeForKey(corridor) = %d, want %d", got, merklewhitelist.ProofSize)
	}
}

func TestScanKeysDirectoryWithMasterKeyRejectsGenericStoredAddressMismatch(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	_, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"address": "NOT_DERIVED",
		"key_type": "aplane.whitelist.v1",
		"bytecode_hex": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"signing_metadata_version": 1
	}`)

	writeKeyFile(t, paths, "default", "NOT_DERIVED", keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("loaded keys = %d, want 0", len(report.Keys))
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", report.Warnings)
	}
	warning := report.Warnings[0]
	if warning.Code != KeyScanWarningLogicSigAddressInvalid {
		t.Fatalf("warning code = %q, want %q", warning.Code, KeyScanWarningLogicSigAddressInvalid)
	}
	if !contains(warning.Reason(), "does not match bytecode-derived address") {
		t.Fatalf("warning reason = %q, want address mismatch", warning.Reason())
	}
}

func TestScanKeysDirectoryWithMasterKeyRejectsDSALSigWithoutBytecode(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	keyJSON, address := testEd25519Key(t)
	var fields map[string]interface{}
	if err := json.Unmarshal(keyJSON, &fields); err != nil {
		t.Fatal(err)
	}
	fields["category"] = CategoryDSALsig
	keyJSON, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("loaded keys = %d, want 0", len(report.Keys))
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", report.Warnings)
	}
	if !contains(report.Warnings[0].Reason(), "missing bytecode") {
		t.Fatalf("warning reason = %q, want missing bytecode", report.Warnings[0].Reason())
	}
}

func TestScanKeysDirectoryWithMasterKeyRejectsDSALSigInvalidBytecode(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	keyJSON, address := testEd25519Key(t)
	var fields map[string]interface{}
	if err := json.Unmarshal(keyJSON, &fields); err != nil {
		t.Fatal(err)
	}
	fields["category"] = CategoryDSALsig
	fields["lsig_bytecode"] = "not-hex"
	fields["salt_counter"] = float64(0)
	keyJSON, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("loaded keys = %d, want 0", len(report.Keys))
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", report.Warnings)
	}
	if !contains(report.Warnings[0].Reason(), "invalid LogicSig bytecode hex") {
		t.Fatalf("warning reason = %q, want invalid bytecode", report.Warnings[0].Reason())
	}
}

func saltedLogicSigForScanTest(t *testing.T) (string, []byte, byte) {
	t.Helper()
	base := []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x81, 0x01}
	result, err := lsigsalt.FindOffCurve(base, lsigsalt.BytecblockLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	return result.Address.String(), result.Bytecode, result.Counter
}

func TestScanKeysDirectoryWithMasterKeyReportRecordsIncompatibleFormatWarnings(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	keysDir := paths.KeysDir("default")
	if err := fsutil.MkdirAll(keysDir); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(keysDir, "OLD.key")
	keyJSON := []byte(`{
		"key_type": "ed25519",
		"public_key": "abc",
		"private_key": "def"
	}`)
	encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKeyReport() error = %v", err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("loaded keys = %d, want 0", len(report.Keys))
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", report.Warnings)
	}
	warning := report.Warnings[0]
	if warning.Code != KeyScanWarningIncompatibleFormat {
		t.Fatalf("warning code = %q, want %q", warning.Code, KeyScanWarningIncompatibleFormat)
	}
	if !contains(warning.Message(), "restore or regenerate") {
		t.Fatalf("warning message = %q, want restore/regenerate guidance", warning.Message())
	}
}

func TestScanKeysDirectoryWithMasterKey_Ed25519WithoutPublicKey(t *testing.T) {
	// Ed25519 keys can have only private_key (no public_key field).
	// deriveAddressAndPublicKeyFromData should derive the public key from the last 32 bytes.
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pk [32]byte
	copy(pk[:], pub)
	address := types.Address(pk).String()

	// Write key without public_key field
	keyData := map[string]interface{}{
		"format_version": CurrentKeyFormatVersion,
		"category":       CategoryEd25519,
		"key_type":       "ed25519",
		"private_key":    hex.EncodeToString(priv),
		// deliberately no "public_key"
	}
	keyJSON, _ := json.MarshalIndent(keyData, "", "  ")
	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	result, err := ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	info, ok := result[address]
	if !ok {
		t.Fatal("address not found in results")
	}
	if info.PublicKeyHex == "" {
		t.Error("public key should be derived from private key")
	}
	if info.PublicKeyHex != hex.EncodeToString(pub) {
		t.Errorf("derived public key = %q, want %q", info.PublicKeyHex, hex.EncodeToString(pub))
	}
}

func TestScanKeysDirectoryWithMasterKey_KeyWithCreatedAt(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())

	keyJSON, address := testEd25519Key(t)

	// Add created_at to the JSON
	var keyData map[string]interface{}
	if err := json.Unmarshal(keyJSON, &keyData); err != nil {
		t.Fatal(err)
	}
	keyData["created_at"] = "2026-01-15T10:30:00Z"
	keyJSON, _ = json.MarshalIndent(keyData, "", "  ")

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	result, err := ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info := result[address]
	if info.CreatedAt != "2026-01-15T10:30:00Z" {
		t.Errorf("CreatedAt = %q, want %q", info.CreatedAt, "2026-01-15T10:30:00Z")
	}
}

func TestReadDecryptedKeyJSONWithMasterKey(t *testing.T) {
	masterKey := testMasterKey(t)
	plaintext := []byte(`{"key_type":"ed25519","public_key":"abc"}`)
	encrypted, _ := crypto.EncryptWithMasterKey(plaintext, masterKey)

	path := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadDecryptedKeyJSONWithMasterKey(path, masterKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Error("content mismatch")
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
