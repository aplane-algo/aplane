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

const (
	// Argon2id parameters for new keystores (OWASP recommended: time≥2, memory≥64MB)
	argon2Time    = 2         // iterations
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

// deriveMasterKeyParams derives a key using explicit Argon2id parameters.
func deriveMasterKeyParams(passphrase, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(passphrase, salt, time, memory, threads, argon2KeyLen)
}

// encryptWithTermKey seals plaintext under one keyring term's key, binding
// the term and the object's logical identity into the AEAD's authenticated
// data. Returns envelope_version 3.
//
// Unexported since phase 2: every caller goes through Keyring.Seal, so no
// code outside this package can hold a raw term key to encrypt with. The
// context is required rather than optional, which is what stops a file from
// being opened as a different object.
func encryptWithTermKey(plaintext, termKey []byte, term int, ctx ObjectContext) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	if term <= 0 {
		return nil, fmt.Errorf("sealing %s requires a term", ctx)
	}
	return sealUnderTerm(plaintext, termKey, term, ctx)
}

// decryptWithTermKey opens a term envelope that must name term and hold the
// object ctx identifies. A wrong key, an edited term header, and an envelope
// belonging to a different object all fail the same way.
//
// Unexported since phase 2: callers go through Keyring.Open.
func decryptWithTermKey(encryptedJSON, termKey []byte, term int, ctx ObjectContext) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	onDisk, err := envelopeTerm(encryptedJSON)
	if err != nil {
		return nil, err
	}
	if onDisk != term {
		return nil, fmt.Errorf(
			"envelope for %s names term %d, not term %d", ctx, onDisk, term,
		)
	}
	return openUnderTerm(encryptedJSON, termKey, term, ctx)
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
