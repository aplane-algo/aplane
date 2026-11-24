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

// sealWithRandomNonce encrypts plaintext with a random nonce, binding aad.
// Returns the nonce and ciphertext separately.
func sealWithRandomNonce(gcm cipher.AEAD, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

const (
	// Argon2id defaults for newly sealed envelopes (OWASP recommended: time>=2, memory>=64 MiB).
	argon2Time    = 2         // iterations
	argon2Memory  = 64 * 1024 // 64 MiB (in KiB)
	argon2Threads = 4         // parallelism
	argon2KeyLen  = 32        // AES-256

	// Accepted Argon2id bounds when opening existing envelopes (store-root
	// keyring v3 and standalone envelope v2). Floor matches today's release
	// defaults; ceiling caps CPU and resident memory under mlockall() before
	// Argon2id runs while allowing future parameter tuning without bumping the
	// envelope version.
	argon2MinTime   = argon2Time
	argon2MaxTime   = 4
	argon2MinMemory = argon2Memory
	argon2MaxMemory = 256 * 1024 // 256 MiB (in KiB)

	gcmNonceBytes = 12
)

// MaxStandaloneEnvelopeBytes is the maximum encoded size accepted for one
// standalone passphrase envelope holding one canonical credential. Larger
// envelopes (the sealed backup manifest, archived policy documents) use
// DecryptStandaloneLimited with their own bound. Callers reading files should
// apply the same limit before allocation.
const MaxStandaloneEnvelopeBytes = 1 << 20

// IsEncrypted checks if data appears to be in encrypted format
func IsEncrypted(data []byte) bool {
	var envelope struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	return json.Unmarshal(data, &envelope) == nil && envelope.EnvelopeVersion > 0
}

const (
	keystoreMetaFile = ".keystore"
	masterSaltLen    = 32
)

// kdfDeriveHook is a test seam. When set, deriveMasterKeyParams reports the
// parameters passed to Argon2id so tests can assert pre-derivation refusal
// and derivation from stored envelope fields. Production leaves it nil.
var kdfDeriveHook func(time, memory uint32, threads uint8)

// deriveMasterKeyParams derives a key using explicit Argon2id parameters.
func deriveMasterKeyParams(passphrase, salt []byte, time, memory uint32, threads uint8) []byte {
	if kdfDeriveHook != nil {
		kdfDeriveHook(time, memory, threads)
	}
	return argon2.IDKey(passphrase, salt, time, memory, threads, argon2KeyLen)
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

	nonce, ciphertext, err := sealWithRandomNonce(gcm, plaintext, nil)
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
	return DecryptStandaloneLimited(encryptedJSON, passphrase, MaxStandaloneEnvelopeBytes)
}

// DecryptStandaloneLimited is DecryptStandalone with a caller-chosen envelope
// size limit, for envelopes larger than one credential such as a backup
// manifest or an archived policy document.
func DecryptStandaloneLimited(encryptedJSON, passphrase []byte, maxEnvelopeBytes int) ([]byte, error) {
	if len(encryptedJSON) == 0 || len(encryptedJSON) > maxEnvelopeBytes {
		return nil, fmt.Errorf(
			"standalone envelope size %d is invalid (maximum %d)",
			len(encryptedJSON), maxEnvelopeBytes,
		)
	}

	var encrypted EncryptedDataStandalone
	if err := decodeJSONStrict(encryptedJSON, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted data: %w", err)
	}
	if encrypted.EnvelopeVersion != 2 {
		return nil, fmt.Errorf(
			"envelope_version %d not supported by standalone decryption (expected 2)",
			encrypted.EnvelopeVersion,
		)
	}
	if err := checkKDFParams("standalone envelope", encrypted.KDFTime, encrypted.KDFMemory, encrypted.KDFThreads); err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(encrypted.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}
	if len(salt) != masterSaltLen {
		return nil, fmt.Errorf("invalid salt length %d (want %d)", len(salt), masterSaltLen)
	}

	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	// Reject invalid nonce lengths before paying Argon2id cost;
	// validateGCMNonce below still guards gcm.Open directly.
	if len(nonce) != gcmNonceBytes {
		return nil, fmt.Errorf("invalid nonce length %d (want %d)", len(nonce), gcmNonceBytes)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	key := deriveMasterKeyParams(passphrase, salt, encrypted.KDFTime, encrypted.KDFMemory, encrypted.KDFThreads)
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
