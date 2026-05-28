// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestWriteLSigFile(t *testing.T) {
	masterKey := testMasterKey(t)
	bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01} // minimal valid TEAL
	address := "LSIGADDR123"

	t.Run("round trip", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())
		params := map[string]string{"recipient": "ALICE", "unlock_round": "1000"}
		signingArgs := []StoredSigningArg{{
			Name:       "secret",
			Type:       "bytes",
			Required:   true,
			ByteLength: 32,
		}}

		err := WriteLSigFile(paths, "default", address, "aplane.timelock.v1", "timelock", params, bytecode, 5, "// teal source", signingArgs, masterKey)
		if err != nil {
			t.Fatalf("WriteLSigFile() error = %v", err)
		}

		// Read and decrypt
		filePath := paths.KeyFilePath("default", address)
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}
		if !crypto.IsEncrypted(data) {
			t.Error("file should be encrypted")
		}

		decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}
		defer crypto.ZeroBytes(decrypted)

		var lsig LSigFile
		if err := json.Unmarshal(decrypted, &lsig); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if lsig.FormatVersion != CurrentKeyFormatVersion {
			t.Errorf("FormatVersion = %d, want %d", lsig.FormatVersion, CurrentKeyFormatVersion)
		}
		if lsig.Category != CategoryGenericLsig {
			t.Errorf("Category = %q, want %q", lsig.Category, CategoryGenericLsig)
		}
		if lsig.Address != address {
			t.Errorf("Address = %q, want %q", lsig.Address, address)
		}
		if lsig.KeyType != "aplane.timelock.v1" {
			t.Errorf("KeyType = %q, want %q", lsig.KeyType, "aplane.timelock.v1")
		}
		if lsig.Template != "timelock" {
			t.Errorf("Template = %q, want %q", lsig.Template, "timelock")
		}
		if lsig.Parameters["recipient"] != "ALICE" {
			t.Errorf("Parameters[recipient] = %q, want %q", lsig.Parameters["recipient"], "ALICE")
		}
		if lsig.BytecodeHex != hex.EncodeToString(bytecode) {
			t.Errorf("BytecodeHex = %q, want %q", lsig.BytecodeHex, hex.EncodeToString(bytecode))
		}
		if lsig.SaltCounter != 5 {
			t.Errorf("SaltCounter = %d, want 5", lsig.SaltCounter)
		}
		if lsig.TEALSource != "// teal source" {
			t.Errorf("TEALSource = %q, want %q", lsig.TEALSource, "// teal source")
		}
		if lsig.SigningMetadataVersion != CurrentSigningMetadataVersion {
			t.Errorf("SigningMetadataVersion = %d, want %d", lsig.SigningMetadataVersion, CurrentSigningMetadataVersion)
		}
		if len(lsig.SigningArgs) != 1 || lsig.SigningArgs[0].Name != "secret" || lsig.SigningArgs[0].ByteLength != 32 {
			t.Errorf("SigningArgs = %+v, want stored secret arg", lsig.SigningArgs)
		}
		if lsig.CreatedAt == "" {
			t.Error("CreatedAt should be set")
		}
	})

	t.Run("directory creation", func(t *testing.T) {
		paths := storepaths.NewPaths(t.TempDir())

		err := WriteLSigFile(paths, "default", "NEWADDR", "aplane.timelock.v1", "timelock", nil, bytecode, 5, "", nil, masterKey)
		if err != nil {
			t.Fatalf("WriteLSigFile() error = %v, should create directory", err)
		}

		// Verify file exists
		filePath := paths.KeyFilePath("default", "NEWADDR")
		if _, err := os.Stat(filePath); err != nil {
			t.Errorf("file should exist: %v", err)
		}
	})
}

func TestLSigFileUnmarshalNormalizesAliases(t *testing.T) {
	var lf LSigFile
	err := json.Unmarshal([]byte(`{
		"format_version":1,
		"category":"generic_lsig",
		"address":"ADDR",
		"key_type":"aplane.timelock.v1",
		"params":{"recipient":"ALICE"},
		"lsig_bytecode":"260101058101",
		"salt_counter":5
	}`), &lf)
	if err != nil {
		t.Fatalf("json.Unmarshal(LSigFile) error = %v", err)
	}
	if lf.Parameters["recipient"] != "ALICE" {
		t.Fatalf("Parameters = %#v, want normalized params", lf.Parameters)
	}
	if lf.BytecodeHex != "260101058101" {
		t.Fatalf("BytecodeHex = %q, want normalized lsig_bytecode", lf.BytecodeHex)
	}
}

func TestLSigFileUnmarshalRejectsConflictingAliases(t *testing.T) {
	var lf LSigFile
	err := json.Unmarshal([]byte(`{
		"category":"generic_lsig",
		"key_type":"aplane.timelock.v1",
		"parameters":{"recipient":"A"},
		"params":{"recipient":"B"},
		"bytecode_hex":"260101058101",
		"salt_counter":5
	}`), &lf)
	if !errors.Is(err, ErrIncompatibleKeyFormat) {
		t.Fatalf("json.Unmarshal(LSigFile conflict) error = %v, want %v", err, ErrIncompatibleKeyFormat)
	}
}

func TestIsGenericLSigType(t *testing.T) {
	// Without registering any templates, all types should be false
	if IsGenericLSigType("ed25519") {
		t.Error("ed25519 should not be a generic LSig type")
	}
	if IsGenericLSigType("aplane.falcon1024.v1") {
		t.Error("aplane.falcon1024.v1 should not be a generic LSig type")
	}
	if IsGenericLSigType("unknown-type") {
		t.Error("unknown type should not be a generic LSig type")
	}
}
