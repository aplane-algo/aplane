// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"

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
	return writeManagedCredentialFile(t, paths, identityID, address+AccountKeyExtension, keyJSON, masterKey)
}

func writeManagedCredentialFile(t *testing.T, paths storepaths.Paths, identityID, name string, keyJSON, masterKey []byte) string {
	t.Helper()
	keysDir := activeKeysDirForTest(t, paths, identityID)
	if err := fsutil.MkdirAll(keysDir); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	filePath := filepath.Join(keysDir, name)
	dataToWrite := keyJSON
	if len(masterKey) > 0 {
		ctx, err := CredentialContextForFile(filePath)
		if err != nil {
			t.Fatalf("CredentialContextForFile(%q): %v", name, err)
		}
		encrypted, err := cryptotest.Keyring(t, masterKey).Seal(keyJSON, ctx)
		if err != nil {
			t.Fatalf("Failed to encrypt key: %v", err)
		}
		dataToWrite = encrypted
	}

	if err := os.WriteFile(filePath, dataToWrite, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	return filePath
}

// readTestContext is the object identity the generic-reader tests seal and
// open under. Its value does not matter; that both sides agree does.
var readTestContext = crypto.AccountKeyContext("READTESTADDRESS")

// mustCredentialContext derives the context a scan will use for path, so a
// test writing a file directly binds it the same way the store would.
func mustCredentialContext(t *testing.T, path string) crypto.ObjectContext {
	t.Helper()
	ctx, err := CredentialContextForFile(path)
	if err != nil {
		t.Fatalf("CredentialContextForFile(%q): %v", path, err)
	}
	return ctx
}

func TestReadAndDecryptFile(t *testing.T) {
	masterKey := testMasterKey(t)

	t.Run("plaintext file rejected", func(t *testing.T) {
		content := []byte(`{"key_type":"ed25519","public_key":"abc"}`)
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}

		_, err := ReadAndDecryptFile(path, nil, readTestContext, "test")
		if err == nil {
			t.Fatal("expected error for plaintext file")
		}
		if !contains(err.Error(), "must be encrypted") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("encrypted file", func(t *testing.T) {
		plaintext := []byte(`{"key_type":"ed25519","public_key":"abc"}`)
		encrypted, err := cryptotest.Keyring(t, masterKey).Seal(plaintext, readTestContext)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, encrypted, 0600); err != nil {
			t.Fatal(err)
		}

		got, err := ReadAndDecryptFile(path, cryptotest.Keyring(t, masterKey), readTestContext, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("decrypted content mismatch")
		}
	})

	t.Run("encrypted file with no keyring", func(t *testing.T) {
		plaintext := []byte(`{"key_type":"ed25519"}`)
		encrypted, err := cryptotest.Keyring(t, masterKey).Seal(plaintext, readTestContext)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, encrypted, 0600); err != nil {
			t.Fatal(err)
		}

		_, err = ReadAndDecryptFile(path, nil, readTestContext, "test")
		if err == nil {
			t.Fatal("expected error for encrypted file without an open keyring")
		}
		if !contains(err.Error(), "the keystore is locked") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := ReadAndDecryptFile("/nonexistent/path.key", cryptotest.Keyring(t, masterKey), readTestContext, "test")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !contains(err.Error(), "failed to read") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("wrong master key", func(t *testing.T) {
		plaintext := []byte(`{"key_type":"ed25519"}`)
		encrypted, err := cryptotest.Keyring(t, masterKey).Seal(plaintext, readTestContext)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(path, encrypted, 0600); err != nil {
			t.Fatal(err)
		}

		wrongKey := testMasterKey(t)
		_, err = ReadAndDecryptFile(path, cryptotest.Keyring(t, wrongKey), readTestContext, "test")
		if err == nil {
			t.Fatal("expected error for wrong master key")
		}
		if !contains(err.Error(), "failed to decrypt") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestScanKeysDirectoryWithKeyring(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		result, err := ScanKeysDirectoryWithKeyring(paths, "default", nil)
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
		genstoretest.MintFirst(t, paths, "default")
		keyJSON, address := testEd25519Key(t)

		writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

		result, err := ScanKeysDirectoryWithKeyring(paths, "default", cryptotest.Keyring(t, masterKey))
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

	t.Run("canonical sentry credential", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		publicKey, privateKey := canonicalFalconComponentPair(t, 0x51)
		payload := NewWitnessPayload(witness.Falcon1024V1, publicKey, privateKey)
		defer payload.ZeroSecrets()
		selector, err := payload.Selector()
		if err != nil {
			t.Fatalf("Selector() error = %v", err)
		}
		keyJSON, err := MarshalPayload(payload)
		if err != nil {
			t.Fatalf("MarshalPayload() error = %v", err)
		}
		writeManagedCredentialFile(t, paths, "default", selector+SentryCredentialExtension, keyJSON, masterKey)

		report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
		if err != nil {
			t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
		}
		if len(report.Warnings) != 0 {
			t.Fatalf("warnings = %#v, want none", report.Warnings)
		}
		info, ok := report.Keys[selector]
		if !ok {
			t.Fatalf("sentry credential %s not loaded", selector)
		}
		if info.Category != CategoryWitness || info.KeyFile != SentryCredentialFilePath(paths, "default", selector) {
			t.Fatalf("loaded sentry credential = %#v", info)
		}
	})

	t.Run("legacy witness key extension is rejected", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		publicKey, privateKey := canonicalFalconComponentPair(t, 0x52)
		payload := NewWitnessPayload(witness.Falcon1024V1, publicKey, privateKey)
		defer payload.ZeroSecrets()
		selector, err := payload.Selector()
		if err != nil {
			t.Fatalf("Selector() error = %v", err)
		}
		keyJSON, err := MarshalPayload(payload)
		if err != nil {
			t.Fatalf("MarshalPayload() error = %v", err)
		}
		legacyPath := writeManagedCredentialFile(t, paths, "default", selector+AccountKeyExtension, keyJSON, masterKey)

		report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
		if err != nil {
			t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
		}
		if len(report.Keys) != 0 || len(report.Warnings) != 1 {
			t.Fatalf("report = %#v, want one rejection", report)
		}
		warning := report.Warnings[0]
		if warning.Code != KeyScanWarningFilenameClassMismatch {
			t.Fatalf("warning code = %q, want %q", warning.Code, KeyScanWarningFilenameClassMismatch)
		}
		for _, want := range []string{legacyPath, SentryCredentialExtension, "Stop apsigner", ".apb", "prior build"} {
			if !contains(warning.Message(), want) {
				t.Fatalf("warning message = %q, want %q", warning.Message(), want)
			}
		}
	})

	t.Run("account payload in sentry class is rejected", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		keyJSON, address := testEd25519Key(t)
		writeManagedCredentialFile(t, paths, "default", address+SentryCredentialExtension, keyJSON, masterKey)

		report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
		if err != nil {
			t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
		}
		if len(report.Keys) != 0 || len(report.Warnings) != 1 || report.Warnings[0].Code != KeyScanWarningFilenameClassMismatch {
			t.Fatalf("report = %#v, want filename class rejection", report)
		}
	})

	t.Run("witness files are validated but never reach decrypt", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		keysDir := activeKeysDirForTest(t, paths, "default")
		if err := fsutil.MkdirAll(keysDir); err != nil {
			t.Fatal(err)
		}
		// A well-formed public witness reference sidecar, as the signer
		// itself writes it.
		publicKey := bytes.Repeat([]byte{7}, witness.Falcon1024PublicKeySize)
		witnessKeyID, err := witness.ID(witness.Falcon1024V1, publicKey)
		if err != nil {
			t.Fatalf("witness.ID() error = %v", err)
		}
		envelope, err := sentryrefs.NewExportEnvelope(witnessKeyID, witness.Falcon1024V1, hex.EncodeToString(publicKey))
		if err != nil {
			t.Fatalf("NewExportEnvelope() error = %v", err)
		}
		envelopeJSON, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("Marshal(envelope) error = %v", err)
		}
		writes := map[string][]byte{
			// Valid sidecar: accepted silently.
			witnessKeyID + ".wit.json": envelopeJSON,
			// Sidecar whose filename is not a canonical Witness Key ID.
			"offline.wit.json": envelopeJSON,
			// Sidecar whose content does not parse.
			strings.Repeat("A", len(witnessKeyID)-1) + "B.wit.json": []byte("not json"),
			// External artifact bundle: aprekey-owned, never a store resident.
			witnessKeyID + ".wit": []byte("encrypted bundle"),
		}
		for name, data := range writes {
			if err := os.WriteFile(filepath.Join(keysDir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		decryptCalls := 0
		report, err := scanKeysDirectoryInternalReport(mustResolveActiveForTest(t, paths), func(string) ([]byte, error) {
			decryptCalls++
			return nil, fmt.Errorf("unexpected decrypt")
		})
		if err != nil {
			t.Fatalf("scanKeysDirectoryInternalReport() error = %v", err)
		}
		if decryptCalls != 0 || len(report.Keys) != 0 {
			t.Fatalf("decrypt calls/keys = %d/%d, want witness files kept away from decrypt", decryptCalls, len(report.Keys))
		}
		got := map[KeyScanWarningCode]int{}
		for _, warning := range report.Warnings {
			got[warning.Code]++
		}
		want := map[KeyScanWarningCode]int{
			KeyScanWarningWitnessMetadataInvalid: 2,
			KeyScanWarningUnexpectedEntry:        1,
		}
		if len(report.Warnings) != 3 || got[KeyScanWarningWitnessMetadataInvalid] != want[KeyScanWarningWitnessMetadataInvalid] || got[KeyScanWarningUnexpectedEntry] != want[KeyScanWarningUnexpectedEntry] {
			t.Fatalf("warnings = %#v, want 2 invalid-metadata + 1 unexpected-entry", report.Warnings)
		}
	})

	t.Run("witness sidecar with mismatched embedded ID is rejected", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		keysDir := activeKeysDirForTest(t, paths, "default")
		if err := fsutil.MkdirAll(keysDir); err != nil {
			t.Fatal(err)
		}
		publicKey := bytes.Repeat([]byte{7}, witness.Falcon1024PublicKeySize)
		witnessKeyID, err := witness.ID(witness.Falcon1024V1, publicKey)
		if err != nil {
			t.Fatalf("witness.ID() error = %v", err)
		}
		otherKeyID, err := witness.ID(witness.Falcon1024V1, bytes.Repeat([]byte{8}, witness.Falcon1024PublicKeySize))
		if err != nil {
			t.Fatalf("witness.ID() error = %v", err)
		}
		envelope, err := sentryrefs.NewExportEnvelope(witnessKeyID, witness.Falcon1024V1, hex.EncodeToString(publicKey))
		if err != nil {
			t.Fatalf("NewExportEnvelope() error = %v", err)
		}
		envelopeJSON, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("Marshal(envelope) error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(keysDir, otherKeyID+".wit.json"), envelopeJSON, 0600); err != nil {
			t.Fatal(err)
		}
		report, err := scanKeysDirectoryInternalReport(mustResolveActiveForTest(t, paths), func(string) ([]byte, error) {
			return nil, fmt.Errorf("unexpected decrypt")
		})
		if err != nil {
			t.Fatalf("scanKeysDirectoryInternalReport() error = %v", err)
		}
		if len(report.Warnings) != 1 || report.Warnings[0].Code != KeyScanWarningWitnessMetadataInvalid {
			t.Fatalf("warnings = %#v, want one ID-mismatch rejection", report.Warnings)
		}
	})

	t.Run("filename address mismatch is skipped", func(t *testing.T) {
		masterKey := testMasterKey(t)
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		keyJSON, address := testEd25519Key(t)

		firstPath := writeKeyFile(t, paths, "default", address, keyJSON, masterKey)
		duplicatePath := filepath.Join(activeKeysDirForTest(t, paths, "default"), "duplicate.key")
		encrypted, err := cryptotest.Keyring(t, masterKey).Seal(keyJSON, mustCredentialContext(t, duplicatePath))
		if err != nil {
			t.Fatalf("encryptWithTermKey() error = %v", err)
		}
		if err := os.WriteFile(duplicatePath, encrypted, 0600); err != nil {
			t.Fatalf("write duplicate key file: %v", err)
		}

		report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
		if err != nil {
			t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
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
		genstoretest.MintFirst(t, paths, "default")
		keyJSON, address := testEd25519Key(t)

		writeKeyFile(t, paths, "default", address, keyJSON, nil)

		report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", nil)
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
		genstoretest.MintFirst(t, paths, "default")
		keysDir := activeKeysDirForTest(t, paths, "default")
		if err := fsutil.MkdirAll(keysDir); err != nil {
			t.Fatal(err)
		}

		// Write a non-.key file
		if err := os.WriteFile(filepath.Join(keysDir, "notes.txt"), []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}

		result, err := ScanKeysDirectoryWithKeyring(paths, "default", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected 0 entries, got %d", len(result))
		}
	})

	t.Run("subdirectories ignored", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		genstoretest.MintFirst(t, paths, "default")
		keysDir := activeKeysDirForTest(t, paths, "default")
		if err := fsutil.MkdirAll(keysDir); err != nil {
			t.Fatal(err)
		}

		// Create a subdirectory (should be skipped)
		if err := os.Mkdir(filepath.Join(keysDir, "subdir"), 0750); err != nil {
			t.Fatal(err)
		}

		result, err := ScanKeysDirectoryWithKeyring(paths, "default", nil)
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
		genstoretest.MintFirst(t, paths, "default")

		// Write a valid key
		keyJSON, address := testEd25519Key(t)
		writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

		// Write a corrupted key file
		keysDir := activeKeysDirForTest(t, paths, "default")
		if err := os.WriteFile(filepath.Join(keysDir, "BADKEY.key"), []byte("not valid data"), 0600); err != nil {
			t.Fatal(err)
		}

		result, err := ScanKeysDirectoryWithKeyring(paths, "default", cryptotest.Keyring(t, masterKey))
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
		genstoretest.MintFirst(t, paths, "default")

		keyJSON1, addr1 := testEd25519Key(t)
		keyJSON2, addr2 := testEd25519Key(t)
		writeKeyFile(t, paths, "default", addr1, keyJSON1, masterKey)
		writeKeyFile(t, paths, "default", addr2, keyJSON2, masterKey)

		result, err := ScanKeysDirectoryWithKeyring(paths, "default", cryptotest.Keyring(t, masterKey))
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

func TestScanKeysDirectoryWithKeyringReportRecordsSaltWarnings(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	keysDir := activeKeysDirForTest(t, paths, "default")
	if err := fsutil.MkdirAll(keysDir); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(keysDir, "GENERIC.key")
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"key_type": "test.generic-policy.v1",
		"lsig_bytecode": "260101058101",
		"signing_metadata_version": 1,
		"created_at": "2026-07-10T12:34:56Z"
	}`)
	encrypted, err := cryptotest.Keyring(t, masterKey).Seal(keyJSON, mustCredentialContext(t, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
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

	missingSalt := NewGenericLSigPayload("test.generic-policy.v1", nil, offCurve, 0, "", nil, "")
	missingSalt.SaltCounter = nil

	onCurvePayload := NewGenericLSigPayload("test.generic-policy.v1", nil, canonicalOnCurveBytecode(t), 0, "", nil, "")

	missingBytecode := NewGenericLSigPayload("test.generic-policy.v1", nil, offCurve, 0, "", nil, "")
	missingBytecode.LogicSigBytecode = nil

	wrongVersion := NewGenericLSigPayload("test.generic-policy.v1", nil, offCurve, 0, "", nil, "")
	wrongVersion.SigningMetadataVersion = CurrentSigningMetadataVersion + 1

	_, badHexErr := ParsePayload([]byte(`{"format_version":1,"category":"generic_lsig","key_type":"test.generic-policy.v1","lsig_bytecode":"zz","salt_counter":0,"signing_metadata_version":1,"created_at":"2026-07-10T00:00:00Z"}`))

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

func TestScanKeysDirectoryWithKeyringLoadsGenericUnderDerivedAddress(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	address, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"key_type": "test.generic-policy.v1",
		"lsig_bytecode": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"signing_metadata_version": 1,
		"created_at": "2026-07-10T12:34:56Z"
	}`)

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", report.Warnings)
	}
	if _, ok := report.Keys[address]; !ok {
		t.Fatalf("derived address %s not loaded", address)
	}
}

func TestScanKeysDirectoryWithKeyringRejectsGenericFilenameAddressMismatch(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	_, bytecode, counter := saltedLogicSigForScanTest(t)
	keyJSON := []byte(`{
		"format_version": 1,
		"category": "generic_lsig",
		"key_type": "test.generic-policy.v1",
		"lsig_bytecode": "` + hex.EncodeToString(bytecode) + `",
		"salt_counter": ` + fmt.Sprintf("%d", counter) + `,
		"signing_metadata_version": 1,
		"created_at": "2026-07-10T12:34:56Z"
	}`)

	writeKeyFile(t, paths, "default", "NOT_DERIVED", keyJSON, masterKey)

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
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

func TestScanKeysDirectoryWithKeyringRejectsDSALSigWithoutBytecode(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
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

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
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

func TestScanKeysDirectoryWithKeyringRejectsDSALSigInvalidBytecode(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
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

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
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

func TestScanKeysDirectoryWithKeyringReportRecordsIncompatibleFormatWarnings(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	keysDir := activeKeysDirForTest(t, paths, "default")
	if err := fsutil.MkdirAll(keysDir); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(keysDir, "OLD.key")
	keyJSON := []byte(`{
		"key_type": "ed25519",
		"public_key": "abc",
		"private_key": "def"
	}`)
	encrypted, err := cryptotest.Keyring(t, masterKey).Seal(keyJSON, mustCredentialContext(t, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
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

func TestScanKeysDirectoryWithKeyringRejectsEd25519WithoutPublicKey(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")

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

	report, err := ScanKeysDirectoryWithKeyringReport(paths, "default", cryptotest.Keyring(t, masterKey))
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

func TestScanKeysDirectoryWithKeyring_KeyWithCreatedAt(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")

	keyJSON, address := testEd25519Key(t)

	// Add created_at to the JSON
	var keyData map[string]interface{}
	if err := json.Unmarshal(keyJSON, &keyData); err != nil {
		t.Fatal(err)
	}
	keyData["created_at"] = "2026-01-15T10:30:00Z"
	keyJSON, _ = json.MarshalIndent(keyData, "", "  ")

	writeKeyFile(t, paths, "default", address, keyJSON, masterKey)

	result, err := ScanKeysDirectoryWithKeyring(paths, "default", cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info := result[address]
	if info.CreatedAt != "2026-01-15T10:30:00Z" {
		t.Errorf("CreatedAt = %q, want %q", info.CreatedAt, "2026-01-15T10:30:00Z")
	}
}

func TestReadDecryptedKeyJSONWithKeyring(t *testing.T) {
	masterKey := testMasterKey(t)
	plaintext := []byte(`{"key_type":"ed25519","public_key":"abc"}`)
	path := filepath.Join(t.TempDir(), "test.key")
	encrypted, err := cryptotest.Keyring(t, masterKey).Seal(plaintext, mustCredentialContext(t, path))
	if err != nil {
		t.Fatalf("encryptWithTermKey() error = %v", err)
	}
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadDecryptedKeyJSONWithKeyring(path, cryptotest.Keyring(t, masterKey))
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

func activeKeysDirForTest(t *testing.T, paths storepaths.Paths, identityID string) string {
	t.Helper()
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active.KeysDir()
}

func mustResolveActiveForTest(t *testing.T, paths storepaths.Paths) storepaths.ActivePaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths, "default")
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active
}

// TestCredentialDoesNotOpenUnderAnotherAddress proves a credential's envelope
// is bound to the account it belongs to, not merely to the store's key.
//
// Without the binding, an attacker with write access to the keys directory can
// swap two credential files and make the signer sign for one account with
// another's key — every byte still decrypts, because one key protects them
// all. The object context is what turns that swap into a decryption failure.
func TestCredentialDoesNotOpenUnderAnotherAddress(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	keyJSON, address := testEd25519Key(t)

	original := writeKeyFile(t, paths, "default", address, keyJSON, masterKey)
	sealed, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", original, err)
	}

	// Byte-for-byte the same ciphertext, filed under a different account.
	const otherAddress = "OTHERADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	moved := filepath.Join(filepath.Dir(original), otherAddress+AccountKeyExtension)
	if err := os.WriteFile(moved, sealed, 0600); err != nil {
		t.Fatalf("WriteFile(%s): %v", moved, err)
	}

	if _, err := ReadDecryptedKeyJSONWithKeyring(moved, cryptotest.Keyring(t, masterKey)); err == nil {
		t.Fatal("credential opened under another address: the object context is not bound")
	}
	// The original still opens, so the failure is the relabeling and not the key.
	if _, err := ReadDecryptedKeyJSONWithKeyring(original, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("original credential no longer opens: %v", err)
	}
}
