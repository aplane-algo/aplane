// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymigration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

func TestNormalizeKeyPayloadStateAddsCanonicalEd25519Header(t *testing.T) {
	legacy := []byte(`{
		"key_type": "ed25519",
		"public_key": "abc",
		"private_key": "def"
	}`)

	normalized, changed, err := NormalizeKeyPayloadState(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if _, err := keys.ValidateCurrentKeyPayload(normalized); err != nil {
		t.Fatalf("ValidateCurrentKeyPayload() error = %v", err)
	}

	var got struct {
		FormatVersion int    `json:"format_version"`
		Category      string `json:"category"`
		KeyType       string `json:"key_type"`
	}
	if err := json.Unmarshal(normalized, &got); err != nil {
		t.Fatal(err)
	}
	if got.FormatVersion != keys.CurrentKeyFormatVersion {
		t.Fatalf("format_version = %d, want %d", got.FormatVersion, keys.CurrentKeyFormatVersion)
	}
	if got.Category != keys.CategoryEd25519 {
		t.Fatalf("category = %q, want %q", got.Category, keys.CategoryEd25519)
	}
	if got.KeyType != "ed25519" {
		t.Fatalf("key_type = %q, want ed25519", got.KeyType)
	}
}

func TestNormalizeKeyPayloadStateSkipsCurrentPayload(t *testing.T) {
	current := []byte(`{
		"format_version": 1,
		"category": "ed25519",
		"key_type": "ed25519",
		"public_key": "abc",
		"private_key": "def"
	}`)

	normalized, changed, err := NormalizeKeyPayloadState(current)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("changed = true, want false")
	}
	if normalized != nil {
		t.Fatal("normalized payload returned for current key")
	}
}

func TestNormalizeKeyPayloadStateRenamesLegacyRuntimeArgs(t *testing.T) {
	legacy := []byte(`{
		"format_version": 1,
		"category": "ed25519",
		"key_type": "ed25519",
		"public_key": "abc",
		"private_key": "def",
		"runtime_args": [
			{"name": "proof", "type": "bytes", "required": true}
		]
	}`)

	normalized, changed, err := NormalizeKeyPayloadState(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if _, err := keys.ValidateCurrentKeyPayload(normalized); err != nil {
		t.Fatalf("ValidateCurrentKeyPayload() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(normalized, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["runtime_args"]; ok {
		t.Fatal("runtime_args remained in repaired payload")
	}
	if _, ok := got["signing_args"]; !ok {
		t.Fatal("signing_args missing from repaired payload")
	}
}

func TestNormalizeKeyPayloadStateRepairsCurrentHeaderWithOutdatedLogicSigState(t *testing.T) {
	bytecode, counter := saltedBytecodeForTest(t)
	currentHeaderOutdatedState := []byte(fmt.Sprintf(`{
		"format_version": 1,
		"category": "generic_lsig",
		"key_type": "aplane.whitelist.v1",
		"bytecode_hex": %q,
		"signing_metadata_version": 1
	}`, hex.EncodeToString(bytecode)))

	normalized, changed, err := NormalizeKeyPayloadState(currentHeaderOutdatedState)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if _, err := keys.ValidateCurrentKeyPayload(normalized); err != nil {
		t.Fatalf("ValidateCurrentKeyPayload() error = %v", err)
	}

	var got struct {
		Address     string `json:"address"`
		SaltCounter *byte  `json:"salt_counter"`
	}
	if err := json.Unmarshal(normalized, &got); err != nil {
		t.Fatal(err)
	}
	if got.Address == "" {
		t.Fatal("address was not repaired")
	}
	if got.SaltCounter == nil {
		t.Fatal("salt_counter was not repaired")
	}
	if *got.SaltCounter != counter {
		t.Fatalf("salt_counter = %d, want %d", *got.SaltCounter, counter)
	}
}

func TestNormalizeKeyPayloadStateRejectsUnrecoverableLogicSigSalt(t *testing.T) {
	legacy := []byte(`{
		"key_type": "aplane.whitelist.v1",
		"bytecode_hex": "260101058101"
	}`)

	_, _, err := NormalizeKeyPayloadState(legacy)
	if err == nil {
		t.Fatal("NormalizeKeyPayloadState() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "missing salt_counter") {
		t.Fatalf("error = %v, want missing salt_counter", err)
	}
}

func TestInferSaltCounterAcceptsMatchingKnownMarkers(t *testing.T) {
	bytecode := bytecodeWithKnownSaltMarkers(42, 42)

	counter, err := inferSaltCounter(bytecode)
	if err != nil {
		t.Fatalf("inferSaltCounter() error = %v", err)
	}
	if counter != 42 {
		t.Fatalf("counter = %d, want 42", counter)
	}
}

func TestInferSaltCounterRejectsConflictingKnownMarkers(t *testing.T) {
	bytecode := bytecodeWithKnownSaltMarkers(42, 43)

	_, err := inferSaltCounter(bytecode)
	if err == nil || !strings.Contains(err.Error(), "conflicting known salt markers") {
		t.Fatalf("inferSaltCounter() error = %v, want conflicting markers", err)
	}
}

func saltedBytecodeForTest(t *testing.T) ([]byte, byte) {
	t.Helper()

	compiled := []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x22}
	result, err := lsigsalt.FindOffCurve(compiled, lsigsalt.BytecblockPreambleLocator)
	if err != nil {
		t.Fatal(err)
	}
	return result.Bytecode, result.Counter
}

func bytecodeWithKnownSaltMarkers(bytecblockCounter, pushbytesCounter byte) []byte {
	bytecode := []byte{0x0c, 0x26, 0x01, 0x01, bytecblockCounter}
	return append(bytecode, lsigsalt.PushbytesSaltMarker(pushbytesCounter)...)
}
