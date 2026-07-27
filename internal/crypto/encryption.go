// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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

	"github.com/aplane-algo/aplane/internal/fsutil"
	"golang.org/x/crypto/argon2"
)

// newGCM creates an AES-256-GCM AEAD from a raw key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

func validateGCMNonce(nonce []byte, gcm cipher.AEAD) error {
	if len(nonce) != gcm.NonceSize() {
		return fmt.Errorf("invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
	}
	return nil
}

// sealWithRandomNonce encrypts plaintext with a random nonce.
// Returns the nonce and ciphertext separately.
func sealWithRandomNonce(gcm cipher.AEAD, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// checkEnvelopeVersion unmarshals the envelope_version from JSON and verifies it matches expected.
func checkEnvelopeVersion(data []byte, expected int, context string) error {
	var v struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("failed to parse encrypted data: %w", err)
	}
	if v.EnvelopeVersion != expected {
		return fmt.Errorf("envelope_version %d not supported by %s (expected %d)", v.EnvelopeVersion, context, expected)
	}
	return nil
}

// buildKeystoreMetadata generates a random salt, derives a master key, and creates
// the metadata struct with a check value. Does not write to disk.
func buildKeystoreMetadata(passphrase []byte) (*KeystoreMetadata, []byte, error) {
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate master salt: %w", err)
	}

	masterKey := DeriveMasterKey(passphrase, salt)

	checkCiphertext, err := encryptCheckValue(masterKey)
	if err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to create check value: %w", err)
	}

	meta := &KeystoreMetadata{
		Version:    CurrentKeystoreMetadataVersion,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Check:      base64.StdEncoding.EncodeToString(checkCiphertext),
		Created:    time.Now().UTC().Format(time.RFC3339),
		KDFTime:    argon2Time,
		KDFMemory:  argon2Memory,
		KDFThreads: argon2Threads,
	}

	return meta, masterKey, nil
}

const (
	// Argon2id parameters for new keystores (OWASP recommended: time≥2, memory≥64MB)
	argon2Time    = 2         // iterations
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4         // parallelism
	argon2KeyLen  = 32        // AES-256

	// Legacy Argon2id parameters used by version 1 keystores. These are frozen:
	// v1 metadata does not store KDF parameters, so changing any of these (or
	// letting them alias the current constants above) would silently change the
	// derived master key and lock existing v1 keystores out as "incorrect
	// passphrase".
	argon2TimeLegacy    = 1
	argon2MemoryLegacy  = 64 * 1024
	argon2ThreadsLegacy = 4

	// CurrentKeystoreMetadataVersion is the .keystore schema version for
	// flat-layout stores. Binaries without generation-layout support have
	// this as their maximum, which is what makes the version bump below a
	// hard old-binary rejection gate.
	CurrentKeystoreMetadataVersion = 2

	// GenerationalKeystoreMetadataVersion marks a store whose active
	// key/key-type namespaces live under identities/<id>/generations/ behind
	// the CURRENT pointer (docs/ARCH_GENERATIONS.md). Older binaries reject
	// it at unlock, rotation, rebuild, and policy-sign — before reading a
	// single stale legacy path.
	GenerationalKeystoreMetadataVersion = 3

	// KeystoreLayoutGenerationsV1 is the layout tag recorded in version-3
	// metadata; the version gate does the rejection, the field documents
	// the reason.
	KeystoreLayoutGenerationsV1 = "generations/v1"
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

// KeystoreMetadata holds keystore-wide encryption metadata.
//
// Version 1: KDF parameters are not stored; implies argon2Time=1, argon2Memory=64MB, argon2Threads=4.
// Version 2: KDF parameters are required so they can be upgraded independently of code.
type KeystoreMetadata struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`  // Base64-encoded master salt
	Check   string `json:"check"` // Base64-encoded AES-GCM encrypted verification value
	Created string `json:"created"`

	// KDF parameters. Version 1 files omit these and use legacy defaults;
	// version 2+ files must set all fields to nonzero values.
	KDFTime    uint32 `json:"kdf_time,omitempty"`
	KDFMemory  uint32 `json:"kdf_memory,omitempty"`
	KDFThreads uint8  `json:"kdf_threads,omitempty"`

	// Layout documents the on-disk store layout for version 3+ metadata
	// (KeystoreLayoutGenerationsV1). The version gate is what rejects the
	// store on older binaries; this field records why.
	Layout string `json:"layout,omitempty"`
}

const (
	// checkPlaintext is the known value encrypted in the Check field.
	checkPlaintext       = "APLANE_OK"
	legacyCheckPlaintext = "ALGOPLANE_OK"
)

// EncryptedDataMasterKey stores encrypted content using master key (no per-file salt)
type EncryptedDataMasterKey struct {
	EnvelopeVersion int    `json:"envelope_version"` // Always 1 for master key encryption
	Nonce           string `json:"nonce"`            // Base64-encoded nonce for AES-GCM
	Ciphertext      string `json:"ciphertext"`       // Base64-encoded encrypted data
}

// DeriveMasterKey derives a key from passphrase and salt using current default parameters.
// Uses Argon2id (memory-hard, GPU-resistant).
// For keystores, prefer VerifyAndDeriveMasterKey which reads stored KDF parameters.
// Caller is responsible for zeroing the returned key when done.
func DeriveMasterKey(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// deriveMasterKeyParams derives a key using explicit Argon2id parameters.
func deriveMasterKeyParams(passphrase, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(passphrase, salt, time, memory, threads, argon2KeyLen)
}

// EncryptWithMasterKey encrypts plaintext using a pre-derived master key.
// Returns envelope_version 1 format (no per-file salt, uses master key).
func EncryptWithMasterKey(plaintext []byte, masterKey []byte) ([]byte, error) {
	gcm, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext)
	if err != nil {
		return nil, err
	}

	encrypted := EncryptedDataMasterKey{
		EnvelopeVersion: 1,
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
	}

	return json.MarshalIndent(encrypted, "", "  ")
}

// DecryptWithMasterKey decrypts ciphertext using a pre-derived master key.
// Only supports envelope_version 1 (master key encryption).
func DecryptWithMasterKey(encryptedJSON []byte, masterKey []byte) ([]byte, error) {
	if err := checkEnvelopeVersion(encryptedJSON, 1, "master key decryption"); err != nil {
		return nil, err
	}

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

	gcm, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}
	if err := validateGCMNonce(nonce, gcm); err != nil {
		return nil, err
	}

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
	meta, masterKey, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		return nil, nil, err
	}
	return writeKeystoreMetadata(keystoreDir, meta, masterKey)
}

// GenerationalMetadataFrom returns a copy of meta stamped with the
// generational layout version. A version-1 record persists no KDF
// parameters (derivation uses frozen legacy constants), so the copy records
// those constants explicitly — key derivation is unchanged, only the layout
// gate moves.
func GenerationalMetadataFrom(meta *KeystoreMetadata) (*KeystoreMetadata, error) {
	if meta == nil {
		return nil, fmt.Errorf("keystore metadata is required")
	}
	bumped := *meta
	if bumped.Version == 1 {
		bumped.KDFTime = argon2TimeLegacy
		bumped.KDFMemory = argon2MemoryLegacy
		bumped.KDFThreads = argon2ThreadsLegacy
	}
	bumped.Version = GenerationalKeystoreMetadataVersion
	bumped.Layout = KeystoreLayoutGenerationsV1
	if err := bumped.validateVersion(); err != nil {
		return nil, err
	}
	return &bumped, nil
}

// IsGenerationalLayout reports whether metadata records the generation
// layout marker.
func (m *KeystoreMetadata) IsGenerationalLayout() bool {
	return m != nil && m.Version >= GenerationalKeystoreMetadataVersion &&
		m.Layout == KeystoreLayoutGenerationsV1
}

// MarshalKeystoreMetadata encodes metadata in the canonical .keystore file
// format after validating it.
func MarshalKeystoreMetadata(meta *KeystoreMetadata) ([]byte, error) {
	if err := meta.validateVersion(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(meta, "", "  ")
}

// CreateKeystoreMetadataGenerational writes version-3 metadata for a store
// whose active namespaces use the generation layout. Older binaries reject
// the store outright instead of reading stale legacy paths.
func CreateKeystoreMetadataGenerational(keystoreDir string, passphrase []byte) (*KeystoreMetadata, []byte, error) {
	meta, masterKey, err := buildKeystoreMetadata(passphrase)
	if err != nil {
		return nil, nil, err
	}
	meta.Version = GenerationalKeystoreMetadataVersion
	meta.Layout = KeystoreLayoutGenerationsV1
	return writeKeystoreMetadata(keystoreDir, meta, masterKey)
}

func writeKeystoreMetadata(keystoreDir string, meta *KeystoreMetadata, masterKey []byte) (*KeystoreMetadata, []byte, error) {

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to marshal keystore metadata: %w", err)
	}

	if err := fsutil.MkdirAll(keystoreDir); err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	metaPath := keystoreDir + "/" + keystoreMetaFile
	if err := fsutil.WriteFile(metaPath, data); err != nil {
		ZeroBytes(masterKey)
		return nil, nil, fmt.Errorf("failed to write keystore metadata: %w", err)
	}

	return meta, masterKey, nil
}

// encryptCheckValue encrypts the check plaintext with the master key.
// Returns raw bytes: nonce (12 bytes) + ciphertext + tag (16 bytes)
func encryptCheckValue(masterKey []byte) ([]byte, error) {
	gcm, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := sealWithRandomNonce(gcm, []byte(checkPlaintext))
	if err != nil {
		return nil, err
	}

	return append(nonce, ciphertext...), nil
}

// decryptCheckValue decrypts the check value with the master key.
// Input is raw bytes: nonce (12 bytes) + ciphertext + tag (16 bytes)
func decryptCheckValue(checkData, masterKey []byte) ([]byte, error) {
	gcm, err := newGCM(masterKey)
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
	if err := meta.validateVersion(); err != nil {
		return nil, err
	}

	return &meta, nil
}

// CreateKeystoreMetadataTemp creates keystore metadata in memory without writing to disk.
// Used for atomic passphrase change operations.
// Returns the metadata and the derived master key.
func CreateKeystoreMetadataTemp(passphrase []byte) (*KeystoreMetadata, []byte, error) {
	return buildKeystoreMetadata(passphrase)
}

// GetMasterSalt returns the decoded master salt from keystore metadata.
func (m *KeystoreMetadata) GetMasterSalt() ([]byte, error) {
	return base64.StdEncoding.DecodeString(m.Salt)
}

func (m *KeystoreMetadata) validateVersion() error {
	if m.Version < 1 || m.Version > GenerationalKeystoreMetadataVersion {
		return fmt.Errorf("unsupported keystore metadata version %d (supported range 1-%d)", m.Version, GenerationalKeystoreMetadataVersion)
	}
	if m.Version >= 2 && (m.KDFTime == 0 || m.KDFMemory == 0 || m.KDFThreads == 0) {
		return fmt.Errorf("keystore metadata version %d has incomplete KDF parameters", m.Version)
	}
	if m.Version >= GenerationalKeystoreMetadataVersion && m.Layout != KeystoreLayoutGenerationsV1 {
		return fmt.Errorf("keystore metadata version %d has unsupported layout %q", m.Version, m.Layout)
	}
	return nil
}

// kdfParams returns the Argon2id parameters for this keystore.
// Version 2+ reads stored values; version 1 returns legacy defaults.
func (m *KeystoreMetadata) kdfParams() (time, memory uint32, threads uint8) {
	if m.Version >= 2 {
		return m.KDFTime, m.KDFMemory, m.KDFThreads
	}
	return argon2TimeLegacy, argon2MemoryLegacy, argon2ThreadsLegacy
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
	KDFTime         uint32 `json:"kdf_time"`
	KDFMemory       uint32 `json:"kdf_memory"`
	KDFThreads      uint8  `json:"kdf_threads"`
}

// EncryptStandalone encrypts plaintext using a passphrase-derived key.
// Produces envelope_version 2 format with an embedded Argon2id salt.
// The output is self-contained: decryptable with only the file + passphrase.
func EncryptStandalone(plaintext, passphrase []byte) ([]byte, error) {
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key := deriveMasterKeyParams(passphrase, salt, argon2Time, argon2Memory, argon2Threads)
	defer ZeroBytes(key)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext)
	if err != nil {
		return nil, err
	}

	encrypted := EncryptedDataStandalone{
		EnvelopeVersion: 2,
		Salt:            base64.StdEncoding.EncodeToString(salt),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		KDFTime:         argon2Time,
		KDFMemory:       argon2Memory,
		KDFThreads:      argon2Threads,
	}

	return json.MarshalIndent(encrypted, "", "  ")
}

// DecryptStandalone decrypts ciphertext using a passphrase.
// Only supports envelope_version 2 (standalone encryption with embedded salt).
func DecryptStandalone(encryptedJSON, passphrase []byte) ([]byte, error) {
	if err := checkEnvelopeVersion(encryptedJSON, 2, "standalone decryption"); err != nil {
		return nil, err
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

	kdfTime, kdfMemory, kdfThreads, err := encrypted.kdfParams()
	if err != nil {
		return nil, err
	}

	key := deriveMasterKeyParams(passphrase, salt, kdfTime, kdfMemory, kdfThreads)
	defer ZeroBytes(key)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if err := validateGCMNonce(nonce, gcm); err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

func (e EncryptedDataStandalone) kdfParams() (time, memory uint32, threads uint8, err error) {
	if e.KDFTime == 0 && e.KDFMemory == 0 && e.KDFThreads == 0 {
		return argon2Time, argon2Memory, argon2Threads, nil
	}
	if e.KDFTime == 0 || e.KDFMemory == 0 || e.KDFThreads == 0 {
		return 0, 0, 0, fmt.Errorf("standalone envelope has incomplete KDF parameters")
	}
	return e.KDFTime, e.KDFMemory, e.KDFThreads, nil
}

// VerifyAndDeriveMasterKey verifies the passphrase and returns the master key if valid.
// Uses KDF parameters from the metadata (version 2+) or legacy defaults (version 1).
// Returns the master key on success, or an error if passphrase is incorrect.
func (m *KeystoreMetadata) VerifyAndDeriveMasterKey(passphrase []byte) ([]byte, error) {
	if err := m.validateVersion(); err != nil {
		return nil, err
	}

	// Get salt
	salt, err := m.GetMasterSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to decode master salt: %w", err)
	}

	// Use stored KDF parameters if present (version 2+), otherwise legacy defaults.
	kdfTime, kdfMemory, kdfThreads := m.kdfParams()

	// Derive master key
	masterKey := deriveMasterKeyParams(passphrase, salt, kdfTime, kdfMemory, kdfThreads)

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

	if !isValidCheckPlaintext(string(plaintext)) {
		ZeroBytes(masterKey)
		return nil, fmt.Errorf("incorrect passphrase (check mismatch)")
	}

	return masterKey, nil
}

func isValidCheckPlaintext(plaintext string) bool {
	return plaintext == checkPlaintext || plaintext == legacyCheckPlaintext
}
