// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// cacheBaseDir is the base directory for cache files.
// Default is "cache" (relative to CWD). Set via SetCacheBaseDir().
var cacheBaseDir = "cache"

// SetCacheBaseDir sets the base directory for all cache files.
// Should be called early in application startup with the data directory.
// Cache files will be stored under <baseDir>/cache/
func SetCacheBaseDir(dataDir string) {
	if dataDir != "" {
		cacheBaseDir = filepath.Join(dataDir, "cache")
	}
}

// getCachePath returns the full path for a cache file.
func getCachePath(filename string) string {
	return filepath.Join(cacheBaseDir, filename)
}

// SignedCache represents cache data with HMAC signature
type SignedCache struct {
	Version int    `json:"version"` // Format version
	Data    string `json:"data"`    // Base64-encoded cache data
	HMAC    string `json:"hmac"`    // HMAC-SHA256 signature
}

// GetOrCreateCacheKey loads the cache signing key, or creates one if it doesn't exist
func GetOrCreateCacheKey() ([]byte, error) {
	keyFile := getCachePath(".cache_key")

	// Check if key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// Create new random key
		key := make([]byte, 32) // 256 bits
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate cache key: %w", err)
		}

		// Ensure cache directory exists
		if err := os.MkdirAll(cacheBaseDir, 0770); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}

		// Write key to file with restrictive permissions
		if err := os.WriteFile(keyFile, key, 0660); err != nil {
			return nil, fmt.Errorf("failed to write cache key: %w", err)
		}

		fmt.Println("✓ Cache integrity protection initialized")
		return key, nil
	}

	// Load existing key
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("invalid cache key length: expected 32 bytes, got %d", len(key))
	}

	return key, nil
}

// signCacheData signs cache data with HMAC-SHA256
func signCacheData(data []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	signature := mac.Sum(nil)
	return hex.EncodeToString(signature)
}

// VerifyHMAC verifies that the HMAC signature matches the data
func VerifyHMAC(data []byte, signatureHex string, key []byte) error {
	// Decode the signature
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid HMAC format: %w", err)
	}

	// Compute expected HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	// Compare using constant-time comparison
	if !hmac.Equal(expected, signature) {
		return fmt.Errorf("HMAC verification failed - cache file has been tampered with")
	}

	return nil
}

// SaveSignedCache saves cache data with HMAC signature
func SaveSignedCache(filePath string, data interface{}, key []byte) error {
	// Serialize the data
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}

	// Compute HMAC
	signature := signCacheData(dataBytes, key)

	// Encode data as base64 to preserve exact bytes
	dataB64 := base64.StdEncoding.EncodeToString(dataBytes)

	// Create signed structure
	signed := SignedCache{
		Version: 1,
		Data:    dataB64,
		HMAC:    signature,
	}

	// Write to file
	output, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signed cache: %w", err)
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(cacheBaseDir, 0770); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	return os.WriteFile(filePath, output, 0660)
}

// ensureCacheDir creates the cache directory or exits fatally on failure.
// This is used by cache loading functions where directory creation failure is unrecoverable.
func ensureCacheDir() {
	if err := os.MkdirAll(cacheBaseDir, 0770); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: Failed to create cache directory %s: %v\n", cacheBaseDir, err)
		os.Exit(1)
	}
}

// loadSignedCacheWithKey loads a signed cache file, handling key management.
// Creates the cache directory if needed (fatal on failure).
// Returns nil on success, or an error that should be treated as a warning.
func loadSignedCacheWithKey(filePath string, target interface{}) error {
	ensureCacheDir()

	key, err := GetOrCreateCacheKey()
	if err != nil {
		return fmt.Errorf("failed to get cache key: %w", err)
	}

	return LoadSignedCache(filePath, key, target)
}

// saveSignedCacheWithKey saves a signed cache file, handling key management.
func saveSignedCacheWithKey(filePath string, data interface{}) error {
	key, err := GetOrCreateCacheKey()
	if err != nil {
		return fmt.Errorf("failed to get cache key: %w", err)
	}

	return SaveSignedCache(filePath, data, key)
}

// LoadSignedCache loads and verifies cache data
func LoadSignedCache(filePath string, key []byte, target interface{}) error {
	// Read file
	raw, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist - this is OK for new installations
			return nil
		}
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	// Parse as signed cache
	var signed SignedCache
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("failed to parse cache file: %w", err)
	}
	if signed.Version == 0 {
		return fmt.Errorf("invalid cache file: missing version")
	}

	// Decode base64 data
	dataBytes, err := base64.StdEncoding.DecodeString(signed.Data)
	if err != nil {
		return fmt.Errorf("failed to decode cache data: %w", err)
	}

	// Verify HMAC
	if err := VerifyHMAC(dataBytes, signed.HMAC, key); err != nil {
		return fmt.Errorf("⚠️  SECURITY WARNING: %w", err)
	}

	// Deserialize data
	if err := json.Unmarshal(dataBytes, target); err != nil {
		return fmt.Errorf("failed to unmarshal cache data: %w", err)
	}

	return nil
}
