// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestMain(m *testing.M) {
	addressderive.RegisterEd25519()
	os.Exit(m.Run())
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
		"created_at":     "2026-07-10T12:34:56Z",
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
		"key_type": "aplane.allowlist.v1",
		"lsig_bytecode": "260101058101",
		"signing_metadata_version": 1,
		"created_at": "2026-07-10T12:34:56Z"
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
	if !warning.IsLogicSigInvariantViolation() {
		t.Fatal("warning should be classified as a LogicSig invariant violation")
	}
	if !contains(warning.Message(), "Failed to validate LogicSig salt metadata") {
		t.Fatalf("warning message = %q", warning.Message())
	}
}

// TestKeyPayloadScanWarningClassification pins the typed-error classification
// chain from codec validation failures to scan warning codes and the audit
// predicate. LogicSig invariant violations (salt, on-curve, bytecode) must
// stay audit-visible; see auditRejectedLogicSigKeys in signerapp/templates.
func TestKeyPayloadScanWarningClassification(t *testing.T) {
	offCurve := canonicalOffCurveBytecode(t)

	missingSalt := NewGenericLSigPayload("aplane.allowlist.v1", nil, offCurve, 0, "", nil, "")
	missingSalt.SaltCounter = nil

	onCurvePayload := NewGenericLSigPayload("aplane.allowlist.v1", nil, canonicalOnCurveBytecode(t), 0, "", nil, "")

	missingBytecode := NewGenericLSigPayload("aplane.allowlist.v1", nil, offCurve, 0, "", nil, "")
	missingBytecode.LogicSigBytecode = nil

	wrongVersion := NewGenericLSigPayload("aplane.allowlist.v1", nil, offCurve, 0, "", nil, "")
	wrongVersion.SigningMetadataVersion = CurrentSigningMetadataVersion + 1

	_, badHexErr := ParsePayload([]byte(`{"format_version":1,"category":"generic_lsig","key_type":"aplane.allowlist.v1","lsig_bytecode":"zz","salt_counter":0,"signing_metadata_version":1,"created_at":"2026-07-10T00:00:00Z"}`))

	cases := []struct {
		name    string
		err     error
		want    KeyScanWarningCode
		audited bool
	}{
		{"missing salt counter", missingSalt.Validate(), KeyScanWarningLogicSigSaltInvalid, true},
		{"on-curve address", onCurvePayload.Validate(), KeyScanWarningLogicSigAddressInvalid, true},
		{"missing bytecode", missingBytecode.Validate(), KeyScanWarningParseLogicSigFailed, true},
		{"undecodable bytecode hex", badHexErr, KeyScanWarningParseLogicSigFailed, true},
		{"wrong signing metadata version", wrongVersion.Validate(), KeyScanWarningIncompatibleFormat, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatal("expected a validation error")
			}
			got := keyPayloadScanWarningCode(tc.err)
			if got != tc.want {
				t.Fatalf("keyPayloadScanWarningCode(%v) = %q, want %q", tc.err, got, tc.want)
			}
			warning := KeyScanWarning{Code: got, KeyFile: "test.key", Err: tc.err}
			if warning.IsLogicSigInvariantViolation() != tc.audited {
				t.Fatalf("IsLogicSigInvariantViolation() for %q = %v, want %v", got, !tc.audited, tc.audited)
			}
		})
	}
}

func TestScanKeysDirectoryWithMasterKeyLoadsGenericUnderDerivedAddress(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	address, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"key_type": "aplane.allowlist.v1",
		"lsig_bytecode": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"signing_metadata_version": 1,
		"created_at": "2026-07-10T12:34:56Z"
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

func TestSignerGeneratedDSAArgSizeIncludesCorridorProofBudget(t *testing.T) {
	if got := signerGeneratedDSAArgSizeForKey(keytypes.CorridorV1); got != merkleallowlist.ProofSize {
		t.Fatalf("signerGeneratedDSAArgSizeForKey(corridor) = %d, want %d", got, merkleallowlist.ProofSize)
	}
}

func TestScanKeysDirectoryWithMasterKeyRejectsGenericFilenameAddressMismatch(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	_, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"key_type": "aplane.allowlist.v1",
		"lsig_bytecode": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"signing_metadata_version": 1,
		"created_at": "2026-07-10T12:34:56Z"
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
	if warning.Code != KeyScanWarningFilenameAddressMismatch {
		t.Fatalf("warning code = %q, want %q", warning.Code, KeyScanWarningFilenameAddressMismatch)
	}
	if !contains(warning.Reason(), "does not match payload-derived address") {
		t.Fatalf("warning reason = %q, want filename mismatch", warning.Reason())
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
	fields["base_key_type"] = "ed25519"
	fields["salt_counter"] = float64(0)
	fields["signing_metadata_version"] = float64(CurrentSigningMetadataVersion)
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
	if !contains(report.Warnings[0].Reason(), "requires lsig_bytecode") {
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
	fields["base_key_type"] = "ed25519"
	fields["lsig_bytecode"] = "not-hex"
	fields["salt_counter"] = float64(0)
	fields["signing_metadata_version"] = float64(CurrentSigningMetadataVersion)
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
	if !contains(report.Warnings[0].Reason(), "invalid lsig_bytecode") {
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

func TestScanKeysDirectoryWithMasterKeyRejectsEd25519WithoutPublicKey(t *testing.T) {
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
		"created_at":     "2026-07-10T12:34:56Z",
		// deliberately no "public_key"
	}
	keyJSON, _ := json.MarshalIndent(keyData, "", "  ")
	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("loaded keys = %d, want 0", len(report.Keys))
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one", report.Warnings)
	}
	if !contains(report.Warnings[0].Reason(), "public key length") {
		t.Fatalf("warning reason = %q, want missing public key rejection", report.Warnings[0].Reason())
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
