// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var testExportMasterKey = []byte("0123456789abcdef0123456789abcdef")

func TestExportKeyUsesSentryCredentialSource(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	identityID := "default"
	selector, keyJSON := testSentryComponentBackupKeyJSON(t)
	encrypted, err := cryptotest.Keyring(t, testExportMasterKey).Seal(keyJSON, crypto.SentryCredentialContext(selector))
	if err != nil {
		t.Fatal(err)
	}
	source := keys.SentryCredentialFilePath(paths, identityID, selector)
	if err := os.WriteFile(source, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if _, _, err := ExportKey(paths, identityID, active.KeysDir(), destination, selector, cryptotest.Keyring(t, testExportMasterKey), []byte("export-passphrase")); err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, selector+".apb")); err != nil {
		t.Fatalf("witness .apb missing: %v", err)
	}
}

func TestExportKeyRejectsAmbiguousManagedCredentialClasses(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	identityID := "default"
	selector, keyJSON := testSentryComponentBackupKeyJSON(t)
	encrypted, err := cryptotest.Keyring(t, testExportMasterKey).Seal(keyJSON, crypto.SentryCredentialContext(selector))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.LegacyKeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, extension := range []string{keys.AccountKeyExtension, keys.SentryCredentialExtension} {
		if err := os.WriteFile(filepath.Join(paths.LegacyKeysDir(), selector+extension), encrypted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = ExportKey(paths, identityID, paths.LegacyKeysDir(), t.TempDir(), selector, cryptotest.Keyring(t, testExportMasterKey), []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "ambiguous managed credential") {
		t.Fatalf("ExportKey() error = %v, want ambiguity rejection", err)
	}
}

func testKeyJSON(t *testing.T, keyType string) []byte {
	t.Helper()
	return keystest.GenericLSigKeyJSON(t, keyType, saltedLogicSigBytecodeForTest(), saltCounterForTest, nil, "")
}

func TestBuildExportPayloadIsCanonicalCredentialOnly(t *testing.T) {
	keyJSON := testKeyJSON(t, "custom.allowlist.v1")
	payload, err := buildExportPayload(keyJSON)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}
	gotKeyJSON, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if !jsonEqualForBackupTest(t, gotKeyJSON, keyJSON) {
		t.Fatalf("credential JSON mismatch\n got: %s\nwant: %s", gotKeyJSON, keyJSON)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	if _, exists := object["backup_bundle"]; exists {
		t.Fatal("credential backup contains obsolete backup_bundle wrapper")
	}
}

func TestParseBackupRejectsInternalBundle(t *testing.T) {
	data := []byte(`{"backup_bundle":1,"payload_version":1,"key":{}}`)
	if _, err := ParseBackup(data); err == nil || !strings.Contains(err.Error(), "unsupported internal backup bundle") {
		t.Fatalf("ParseBackup() error = %v, want pre-release bundle rejection", err)
	}
}

func jsonEqualForBackupTest(t *testing.T, left, right []byte) bool {
	t.Helper()
	var leftValue any
	var rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatalf("json.Unmarshal(left) error = %v", err)
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		t.Fatalf("json.Unmarshal(right) error = %v", err)
	}
	return jsonObjectsEqual(leftValue, rightValue)
}

func jsonObjectsEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func mintFirstGenerationForBackupTest(t *testing.T, paths storepaths.Paths) {
	t.Helper()
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, "default", genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-initialize",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_785_200_000, 0),
	}); err != nil {
		t.Fatalf("Mint(first): %v", err)
	}
}
