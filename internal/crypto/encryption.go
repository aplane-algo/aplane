// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters (OWASP recommended)
	argon2Time    = 1         // iterations
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4         // parallelism
	argon2KeyLen  = 32        // AES-256
)

// EncryptedData stores the encrypted content with metadata
type EncryptedData struct {
	EnvelopeVersion int    `json:"envelope_version"` // Encryption envelope format version
	Salt            string `json:"salt"`             // Base64-encoded salt for PBKDF2
	Nonce           string `json:"nonce"`            // Base64-encoded nonce for AES-GCM
	Ciphertext      string `json:"ciphertext"`       // Base64-encoded encrypted data
}

// IsEncrypted checks if data appears to be in encrypted format
func IsEncrypted(data []byte) bool {
	var encrypted EncryptedData
	return json.Unmarshal(data, &encrypted) == nil && encrypted.EnvelopeVersion > 0
}

// ============================================================================
// Master Key encryption (envelope_version 1)
// ============================================================================
// These functions use a pre-derived master key instead of per-file PBKDF2.
// The master key is derived once at unlock time from the keystore salt.

const (
	keystoreMetaFile = ".keystore"
	masterSaltLen    = 32
)

// KeystoreMetadata holds keystore-wide encryption metadata
type KeystoreMetadata struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`  // Base64-encoded master salt
	Check   string `json:"check"` // Base64-encoded AES-GCM encrypted verification value
	Created string `json:"created"`
}

const (
	// checkPlaintext is the known value encrypted in the Check field
	checkPlaintext = "ALGOPLANE_OK"
)

// EncryptedDataMasterKey stores encrypted content using master key (no per-file salt)
type EncryptedDataMasterKey struct {
	EnvelopeVersion int    `json:"envelope_version"` // Always 1 for master key encryption
	Nonce           string `json:"nonce"`            // Base64-encoded nonce for AES-GCM
	Ciphertext      string `json:"ciphertext"`       // Base64-encoded encrypted data
}

// DeriveMasterKey derives the keystore master key from passphrase and salt.
// Uses Argon2id (memory-hard, GPU-resistant).
// This should be called once at unlock time.
// Caller is responsible for zeroing the returned key when done.
func DeriveMasterKey(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// EncryptWithMasterKey encrypts plaintext using a pre-derived master key.
// Returns envelope_version 1 format (no per-file salt, uses master key).
func EncryptWithMasterKey(plaintext []byte, masterKey []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Create encrypted data structure (master key - no per-file salt)
	encrypted := EncryptedDataMasterKey{
		EnvelopeVersion: 1,
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
	}

	// Marshal to JSON
	return json.MarshalIndent(encrypted, "", "  ")
}

// DecryptWithMasterKey decrypts ciphertext using a pre-derived master key.
// Only supports envelope_version 1 (master key encryption).
func DecryptWithMasterKey(encryptedJSON []byte, masterKey []byte) ([]byte, error) {
	// First check the envelope version
	var versionCheck struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(encryptedJSON, &versionCheck); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted data: %w", err)
	}

	if versionCheck.EnvelopeVersion != 1 {
		return nil, fmt.Errorf("envelope_version %d not supported by master key decryption (expected 1)", versionCheck.EnvelopeVersion)
	}

	// Parse master key encrypted structure
	var encrypted EncryptedDataMasterKey
	if err := json.Unmarshal(encryptedJSON, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted data: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Create AES cipher with master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// CreateKeystoreMetadata creates a new keystore metadata file with a random master salt.
// The passphrase is used to derive the master key and create the check field.
// Returns the metadata and the derived master key.
func CreateKeystoreMetadata(keystoreDir string, passphrase []byte) (*KeystoreMetadata, []byte, error) {
	// Generate random master salt
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate master salt: %w", err)
	}

	// Derive master key
	masterKey := DeriveMasterKey(passphrase, salt)

	// Create check value: encrypt known plaintext with master key
	checkCiphertext, err := encryptCheckValue(masterKey)
	if err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to create check value: %w", err)
	}

	meta := &KeystoreMetadata{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Check:   base64.StdEncoding.EncodeToString(checkCiphertext),
		Created: time.Now().UTC().Format(time.RFC3339),
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to marshal keystore metadata: %w", err)
	}

	// Ensure keystore directory exists
	if err := os.MkdirAll(keystoreDir, 0750); err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// Write to file
	metaPath := keystoreDir + "/" + keystoreMetaFile
	if err := os.WriteFile(metaPath, data, 0600); err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to write keystore metadata: %w", err)
	}

	return meta, masterKey, nil
}

// encryptCheckValue encrypts the check plaintext with the master key.
// Returns raw bytes: nonce (12 bytes) + ciphertext + tag (16 bytes)
func encryptCheckValue(masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(checkPlaintext), nil)
	return ciphertext, nil
}

// decryptCheckValue decrypts the check value with the master key.
// Input is raw bytes: nonce (12 bytes) + ciphertext + tag (16 bytes)
func decryptCheckValue(checkData, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(checkData) < gcm.NonceSize() {
		return nil, fmt.Errorf("check data too short")
	}

	nonce := checkData[:gcm.NonceSize()]
	ciphertext := checkData[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// LoadKeystoreMetadata loads the keystore metadata file.
// Returns nil if the file doesn't exist (v1 keystore).
func LoadKeystoreMetadata(keystoreDir string) (*KeystoreMetadata, error) {
	metaPath := keystoreDir + "/" + keystoreMetaFile
	return LoadKeystoreMetadataFrom(metaPath)
}

// LoadKeystoreMetadataFrom loads keystore metadata from a specific file path.
func LoadKeystoreMetadataFrom(metaPath string) (*KeystoreMetadata, error) {
	data, err := os.ReadFile(metaPath)
	if os.IsNotExist(err) {
		return nil, nil // No metadata file
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore metadata: %w", err)
	}

	var meta KeystoreMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse keystore metadata: %w", err)
	}

	return &meta, nil
}

// CreateKeystoreMetadataTemp creates keystore metadata in memory without writing to disk.
// Used for atomic passphrase change operations.
// Returns the metadata and the derived master key.
func CreateKeystoreMetadataTemp(passphrase []byte) (*KeystoreMetadata, []byte, error) {
	// Generate random master salt
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate master salt: %w", err)
	}

	// Derive master key
	masterKey := DeriveMasterKey(passphrase, salt)

	// Create check value: encrypt known plaintext with master key
	checkCiphertext, err := encryptCheckValue(masterKey)
	if err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to create check value: %w", err)
	}

	meta := &KeystoreMetadata{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Check:   base64.StdEncoding.EncodeToString(checkCiphertext),
		Created: time.Now().UTC().Format(time.RFC3339),
	}

	return meta, masterKey, nil
}

// GetMasterSalt returns the decoded master salt from keystore metadata.
func (m *KeystoreMetadata) GetMasterSalt() ([]byte, error) {
	return base64.StdEncoding.DecodeString(m.Salt)
}

// KeystoreMetadataExistsIn checks if the .keystore metadata file exists in the specified directory.
func KeystoreMetadataExistsIn(keystoreDir string) bool {
	metaPath := keystoreDir + "/" + keystoreMetaFile
	_, err := os.Stat(metaPath)
	return err == nil
}

// VerifyPassphraseWithMetadata verifies the passphrase using the .keystore metadata file.
// This replaces VerifyPassphraseBytesIn for keystores using master key encryption.
// Returns nil on success, or an error if passphrase is incorrect.
func VerifyPassphraseWithMetadata(passphrase []byte, keystoreDir string) error {
	meta, err := LoadKeystoreMetadata(keystoreDir)
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("keystore not initialized (missing .keystore file)")
	}

	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		return err
	}
	ZeroBytes(masterKey) // Don't need the key, just verifying
	return nil
}

// VerifyMasterKeyWithMetadata verifies a raw master key against the keystore check value.
// Unlike VerifyPassphraseWithMetadata, this skips Argon2id derivation — the provided bytes
// are used directly as the master key. Used with passphrase_command_kind: master_key.
func VerifyMasterKeyWithMetadata(masterKey []byte, keystoreDir string) error {
	meta, err := LoadKeystoreMetadata(keystoreDir)
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("keystore not initialized (missing .keystore file)")
	}

	checkData, err := base64.StdEncoding.DecodeString(meta.Check)
	if err != nil {
		return fmt.Errorf("failed to decode check value: %w", err)
	}

	plaintext, err := decryptCheckValue(checkData, masterKey)
	if err != nil {
		return fmt.Errorf("incorrect master key")
	}

	if string(plaintext) != checkPlaintext {
		return fmt.Errorf("incorrect master key (check mismatch)")
	}

	return nil
}

// ============================================================================
// Standalone encryption (envelope_version 2)
// ============================================================================
// These functions produce self-contained encrypted files. Each file embeds its
// own Argon2id salt so it can be decrypted with only the file + passphrase —
// no .keystore metadata is needed. Used for backup/export files.

// EncryptedDataStandalone stores encrypted content with an embedded salt (envelope_version 2).
type EncryptedDataStandalone struct {
	EnvelopeVersion int    `json:"envelope_version"` // Always 2 for standalone encryption
	Salt            string `json:"salt"`             // Base64-encoded 32-byte random salt
	Nonce           string `json:"nonce"`            // Base64-encoded 12-byte nonce for AES-GCM
	Ciphertext      string `json:"ciphertext"`       // Base64-encoded encrypted data
}

// EncryptStandalone encrypts plaintext using a passphrase-derived key.
// Produces envelope_version 2 format with an embedded Argon2id salt.
// The output is self-contained: decryptable with only the file + passphrase.
func EncryptStandalone(plaintext, passphrase []byte) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from passphrase
	key := DeriveMasterKey(passphrase, salt)
	defer ZeroBytes(key)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	encrypted := EncryptedDataStandalone{
		EnvelopeVersion: 2,
		Salt:            base64.StdEncoding.EncodeToString(salt),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
	}

	return json.MarshalIndent(encrypted, "", "  ")
}

// DecryptStandalone decrypts ciphertext using a passphrase.
// Only supports envelope_version 2 (standalone encryption with embedded salt).
func DecryptStandalone(encryptedJSON, passphrase []byte) ([]byte, error) {
	// Check envelope version
	var versionCheck struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(encryptedJSON, &versionCheck); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted data: %w", err)
	}

	if versionCheck.EnvelopeVersion != 2 {
		return nil, fmt.Errorf("envelope_version %d not supported by standalone decryption (expected 2)", versionCheck.EnvelopeVersion)
	}

	var encrypted EncryptedDataStandalone
	if err := json.Unmarshal(encryptedJSON, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted data: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(encrypted.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Derive key from passphrase and embedded salt
	key := DeriveMasterKey(passphrase, salt)
	defer ZeroBytes(key)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// VerifyAndDeriveMasterKey verifies the passphrase and returns the master key if valid.
// This replaces the need for a separate .passphrase_check file.
// Returns the master key on success, or an error if passphrase is incorrect.
func (m *KeystoreMetadata) VerifyAndDeriveMasterKey(passphrase []byte) ([]byte, error) {
	// Get salt
	salt, err := m.GetMasterSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to decode master salt: %w", err)
	}

	// Derive master key
	masterKey := DeriveMasterKey(passphrase, salt)

	// Verify by decrypting the check value
	checkData, err := base64.StdEncoding.DecodeString(m.Check)
	if err != nil {
		ZeroBytes(masterKey)
		return nil, fmt.Errorf("failed to decode check value: %w", err)
	}

	plaintext, err := decryptCheckValue(checkData, masterKey)
	if err != nil {
		ZeroBytes(masterKey)
		return nil, fmt.Errorf("incorrect passphrase")
	}

	if string(plaintext) != checkPlaintext {
		ZeroBytes(masterKey)
		return nil, fmt.Errorf("incorrect passphrase (check mismatch)")
	}

	return masterKey, nil
}
