// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// KeyScanInfo holds information about a scanned key file.
// This allows scanning to extract all needed info in a single decrypt operation,
// avoiding the need to re-decrypt keys for /keys API or signing budget calculation.
type KeyScanInfo struct {
	KeyFile      string // Path to the key file
	KeyType      string // Key type (ed25519, falcon1024-v1, timelock-v3, etc.)
	LsigSize     int    // Total LogicSig size in bytes (bytecode + signature), 0 for ed25519
	PublicKeyHex string // Hex-encoded public key (for /keys API)
	CreatedAt    string // RFC 3339 creation timestamp (empty for legacy keys)
}

// ReadDecryptedKeyJSONWithMasterKey reads a key file and decrypts with the master key.
// Only supports envelope_version 2 files.
func ReadDecryptedKeyJSONWithMasterKey(keyFile string, masterKey []byte) ([]byte, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Check if the file is encrypted
	if !crypto.IsEncrypted(data) {
		// File is not encrypted, return as-is
		return data, nil
	}

	if len(masterKey) == 0 {
		return nil, fmt.Errorf("key file is encrypted but no master key provided")
	}

	// Decrypt with master key (envelope_version 2)
	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key file with master key: %w", err)
	}
	return decrypted, nil
}

// ScanKeysDirectoryWithMasterKey scans the identity-scoped keys subdirectory using a master key for decryption.
// Only supports envelope_version 2 files.
func ScanKeysDirectoryWithMasterKey(identityID string, masterKey []byte) (map[string]KeyScanInfo, error) {
	return scanKeysDirectoryInternal(identityID, func(keyFile string) ([]byte, error) {
		return ReadDecryptedKeyJSONWithMasterKey(keyFile, masterKey)
	})
}

// scanKeysDirectoryInternal is the shared implementation for scanning keys.
// The decryptFunc parameter allows using either passphrase or master key decryption.
func scanKeysDirectoryInternal(identityID string, decryptFunc func(keyFile string) ([]byte, error)) (map[string]KeyScanInfo, error) {
	keysMap := make(map[string]KeyScanInfo)

	keysDir := utilkeys.KeysDir(identityID)

	// Ensure keys directory exists
	if err := os.MkdirAll(keysDir, 0770); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Read keys directory
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys directory: %w", err)
	}

	// Scan for .key files (all key types: Ed25519, Falcon-1024, LogicSigs)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}

		keyFile := utilkeys.KeyFilePath(identityID, strings.TrimSuffix(entry.Name(), ".key"))

		// Read and decrypt the file ONCE to extract all needed info
		data, err := decryptFunc(keyFile)
		if err != nil {
			fmt.Printf("Warning: Failed to read key file %s: %v\n", keyFile, err)
			continue
		}

		// Detect key type from content
		keyType, err := DetectKeyTypeFromData(data)
		if err != nil {
			crypto.ZeroBytes(data)
			fmt.Printf("Warning: Failed to detect key type for %s: %v\n", keyFile, err)
			continue
		}

		// Extract address, public key, and bytecode based on key type
		var address string
		var publicKeyHex string
		var lsigSize int

		if IsGenericLSigType(keyType) {
			// For generic LogicSig files, address and bytecode are stored directly
			var lsigFile LSigFile
			if err := json.Unmarshal(data, &lsigFile); err != nil {
				crypto.ZeroBytes(data)
				fmt.Printf("Warning: Failed to parse lsig file %s: %v\n", keyFile, err)
				continue
			}
			address = lsigFile.Address
			// Generic LSigs have no crypto signature, just bytecode
			lsigSize = len(lsigFile.BytecodeHex) / 2
			// No public key for generic LSigs
		} else {
			// For DSA keys (Ed25519, Falcon-1024)
			// Try to derive address from stored bytecode first (avoids algod round-trip)
			bytecode := extractBytecode(data)
			if len(bytecode) > 0 {
				// LSig key with stored bytecode — derive address locally
				addr, addrErr := logicSigAddress(bytecode)
				if addrErr != nil {
					crypto.ZeroBytes(data)
					fmt.Printf("Warning: Failed to derive address from bytecode for %s: %v\n", keyFile, addrErr)
					continue
				}
				address = addr
				publicKeyHex = extractPublicKeyHex(data)
				lsigSize = len(bytecode) + logicsigdsa.GetCryptoSignatureSize(keyType)
			} else {
				// Ed25519 native key (no bytecode) — derive from public key
				address, publicKeyHex, err = deriveAddressAndPublicKeyFromData(data, keyType)
				if err != nil {
					crypto.ZeroBytes(data)
					fmt.Printf("Warning: Failed to derive address for %s: %v\n", keyFile, err)
					continue
				}
			}
		}

		createdAt := extractCreatedAt(data)
		crypto.ZeroBytes(data) // Zero after all processing complete

		keysMap[address] = KeyScanInfo{
			KeyFile:      keyFile,
			KeyType:      keyType,
			LsigSize:     lsigSize,
			PublicKeyHex: publicKeyHex,
			CreatedAt:    createdAt,
		}
	}

	return keysMap, nil
}

// deriveAddressAndPublicKeyFromData derives the Algorand address and extracts the public key
// from already-decrypted key data. This avoids re-reading and re-decrypting the file.
func deriveAddressAndPublicKeyFromData(data []byte, keyType string) (address string, publicKeyHex string, err error) {
	// Parse the key data to get public key
	var keyData struct {
		PublicKeyHex  string            `json:"public_key"`
		PrivateKeyHex string            `json:"private_key"`
		Params        map[string]string `json:"params,omitempty"`
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	publicKeyHex = keyData.PublicKeyHex

	// Handle Ed25519 keys that might be missing public key
	if keyType == "ed25519" && publicKeyHex == "" {
		// For Ed25519, the public key is the last 32 bytes of the 64-byte private key
		privBytes, err := hex.DecodeString(keyData.PrivateKeyHex)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode Ed25519 private key: %w", err)
		}
		defer crypto.ZeroBytes(privBytes)
		if len(privBytes) != 64 {
			return "", "", fmt.Errorf("invalid Ed25519 private key length: expected 64 bytes, got %d", len(privBytes))
		}
		publicKeyHex = hex.EncodeToString(privBytes[32:])
	}

	// Use the registry to get the appropriate address deriver
	deriver, err := util.GetAddressDeriver(keyType)
	if err != nil {
		return "", "", fmt.Errorf("no address deriver for key type %s: %w", keyType, err)
	}

	address, err = deriver.DeriveAddress(publicKeyHex, keyData.Params)
	if err != nil {
		return "", "", err
	}

	return address, publicKeyHex, nil
}

// extractBytecode extracts the LogicSig bytecode from key data.
// Returns nil if no bytecode is present (e.g., native Ed25519 keys).
func extractBytecode(data []byte) []byte {
	var keyData struct {
		LsigBytecode string `json:"lsig_bytecode"`
		BytecodeHex  string `json:"bytecode_hex"`
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil
	}

	bytecodeHex := keyData.LsigBytecode
	if bytecodeHex == "" {
		bytecodeHex = keyData.BytecodeHex
	}
	if bytecodeHex == "" {
		return nil
	}

	bytecode, err := hex.DecodeString(bytecodeHex)
	if err != nil {
		return nil
	}
	return bytecode
}

// extractPublicKeyHex extracts the public key hex from key data.
func extractPublicKeyHex(data []byte) string {
	var keyData struct {
		PublicKeyHex string `json:"public_key"`
	}
	_ = json.Unmarshal(data, &keyData)
	return keyData.PublicKeyHex
}

// logicSigAddress computes the LogicSig address from bytecode.
func logicSigAddress(bytecode []byte) (string, error) {
	lsig := sdkcrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	addr, err := lsig.Address()
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// extractCreatedAt extracts the created_at timestamp from key data.
// Returns empty string if not present (legacy keys).
func extractCreatedAt(data []byte) string {
	var partial struct {
		CreatedAt string `json:"created_at"`
	}
	_ = json.Unmarshal(data, &partial)
	return partial.CreatedAt
}

func DetectKeyTypeFromData(data []byte) (string, error) {
	// All key files now use "key_type" field
	var keyTypeCheck struct {
		KeyType string `json:"key_type"`
	}
	if err := json.Unmarshal(data, &keyTypeCheck); err != nil {
		return "", fmt.Errorf("failed to unmarshal key type: %w", err)
	}

	if keyTypeCheck.KeyType != "" {
		return keyTypeCheck.KeyType, nil
	}

	return "", fmt.Errorf("key file missing required 'key_type' field")
}
