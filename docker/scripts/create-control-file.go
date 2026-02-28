// Create store metadata and passphrase file for Docker playground
// Usage: go run create-control-file.go <user-directory> <passphrase-file>
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters (must match internal/crypto/encryption.go)
	argon2Time    = 1         // iterations
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4         // parallelism
	argon2KeyLen  = 32        // AES-256

	masterSaltLen  = 32
	checkPlaintext = "ALGOPLANE_OK" // Must match internal/crypto/encryption.go
)

// KeystoreMetadata matches the format in internal/crypto/encryption.go
type KeystoreMetadata struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`
	Check   string `json:"check"`
	Created string `json:"created"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: create-control-file <user-directory> <passphrase-file>")
		os.Exit(1)
	}
	userDir := os.Args[1]
	passphraseFile := os.Args[2]

	passphrase := "playground"

	// Ensure user directory exists
	if err := os.MkdirAll(userDir, 0750); err != nil {
		panic(fmt.Errorf("failed to create user directory: %w", err))
	}

	// Generate random master salt (32 bytes)
	salt := make([]byte, masterSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	// Derive master key from passphrase using Argon2id
	masterKey := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Create check value: encrypt known plaintext with master key
	// Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// gcm.Seal prepends nonce to ciphertext when dst is nonce
	checkCiphertext := gcm.Seal(nonce, nonce, []byte(checkPlaintext), nil)

	// Create store metadata
	meta := KeystoreMetadata{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Check:   base64.StdEncoding.EncodeToString(checkCiphertext),
		Created: time.Now().UTC().Format(time.RFC3339),
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		panic(err)
	}

	// Write to .keystore file in user directory
	keystorePath := filepath.Join(userDir, ".keystore")
	if err := os.WriteFile(keystorePath, jsonData, 0600); err != nil {
		panic(err)
	}
	fmt.Printf("Created store metadata: %s\n", keystorePath)

	// Create keys directory (users/default/keys/)
	keysDir := filepath.Join(userDir, "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		panic(fmt.Errorf("failed to create keys directory: %w", err))
	}
	fmt.Printf("Created keys directory: %s\n", keysDir)

	// Write passphrase file (for headless autostart)
	if err := os.WriteFile(passphraseFile, []byte(passphrase+"\n"), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("Created passphrase file: %s\n", passphraseFile)
}
