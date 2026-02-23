// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package backup

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReadmeContent is the README.md content written to backup directories
const ReadmeContent = `# Signer Key Backup

This directory contains encrypted private keys backed up from Signer.

## File Format

Each ` + "`.apb`" + ` file is named after the Algorand address it controls (e.g., ` + "`ABC123...XYZ.apb`" + `).

Each file is self-contained: it can be decrypted with only the file and the export passphrase (no additional metadata files are needed).

Keys that use custom templates (added via ` + "`apstore add-template`" + ` or ` + "`apstore add-falcon-template`" + `) embed the template definition within the encrypted payload. On restore, the template is automatically extracted and saved to the keystore.

## Encryption Format (envelope_version 2)

Each ` + "`.apb`" + ` file is a JSON document with four fields:

- ` + "`envelope_version`" + `: Always 2 (self-contained standalone format)
- ` + "`salt`" + `: Base64-encoded 32-byte random salt for Argon2id key derivation
- ` + "`nonce`" + `: Base64-encoded 12-byte random nonce for AES-256-GCM
- ` + "`ciphertext`" + `: Base64-encoded AES-256-GCM encrypted data

### Key Derivation

The encryption key is derived using Argon2id with the following parameters:

- Time (iterations): 1
- Memory: 64 MB (65536 KiB)
- Threads: 4
- Output key length: 32 bytes (AES-256)

### Decryption Steps

1. Parse the JSON file
2. Base64-decode the ` + "`salt`" + `, ` + "`nonce`" + `, and ` + "`ciphertext`" + ` fields
3. Derive the AES-256 key: ` + "`Argon2id(passphrase, salt, time=1, memory=64MB, threads=4, keyLen=32)`" + `
4. Decrypt using AES-256-GCM with the derived key and nonce
5. The decrypted plaintext is a JSON object containing the key type, public key (hex), and private key (hex)

## Restoring Keys

### Using apstore (Recommended)

Restore all keys:

` + "```bash" + `
apstore restore all /path/to/this/backup
` + "```" + `

Or restore a single key:

` + "```bash" + `
apstore restore <ADDRESS> /path/to/this/backup
` + "```" + `

You will be prompted for the export passphrase (to decrypt the backup) and the store passphrase (to encrypt into the target keystore).

### Manual Decryption

If you need to decrypt manually, use the Argon2id and AES-256-GCM parameters documented above. Most languages have libraries for both (e.g., Python ` + "`argon2-cffi`" + ` + ` + "`cryptography`" + `, Go ` + "`golang.org/x/crypto/argon2`" + ` + ` + "`crypto/aes`" + `).

## Security Notes

- **Keep this backup secure**: These files contain your private keys
- **Remember your export passphrase**: Without it, the keys cannot be decrypted
- **Store offline**: Consider keeping backups on offline media (USB drives, etc.)
- **Multiple copies**: Keep backups in multiple secure locations

---
*Backup created by apstore*
`

// WriteReadme writes the README.md file to the backup directory
func WriteReadme(destDir string) error {
	readmePath := filepath.Join(destDir, "README.md")
	// #nosec G306 - README files are meant to be world-readable
	if err := os.WriteFile(readmePath, []byte(ReadmeContent), 0644); err != nil {
		return fmt.Errorf("failed to write README.md: %w", err)
	}
	return nil
}
