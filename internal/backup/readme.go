// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReadmeContent is the README.md content written to backup directories
const ReadmeContent = `# Signer Key Backup

This backup contains encrypted private keys backed up from Signer.

Backups are normally packaged as a .tar.gz archive containing this README and
an apb/ directory. If you extracted the archive first, the same
instructions apply to the extracted directory.

## File Format

Each ` + "`.apb`" + ` file is named after the Algorand address it controls (e.g., ` + "`ABC123...XYZ.apb`" + `).

Each file is self-contained: it can be decrypted with only the file and the export passphrase (no additional metadata files are needed).

Template-backed keys may embed their installed template definition within the encrypted payload. On restore, the template is automatically extracted and saved to the keystore when no authoritative destination template already exists.

## Encryption Format (envelope_version 2)

Each ` + "`.apb`" + ` file is a JSON document with four fields:

- ` + "`envelope_version`" + `: Always 2 (self-contained standalone format)
- ` + "`salt`" + `: Base64-encoded 32-byte random salt for Argon2id key derivation
- ` + "`nonce`" + `: Base64-encoded 12-byte random nonce for AES-256-GCM
- ` + "`ciphertext`" + `: Base64-encoded AES-256-GCM encrypted data

### Key Derivation

The encryption key is derived using Argon2id with the following parameters:

- Time (iterations): 2
- Memory: 64 MB (65536 KiB)
- Threads: 4
- Output key length: 32 bytes (AES-256)

### Decryption Steps

1. Parse the JSON file
2. Base64-decode the ` + "`salt`" + `, ` + "`nonce`" + `, and ` + "`ciphertext`" + ` fields
3. Derive the AES-256 key: ` + "`Argon2id(passphrase, salt, time=2, memory=64MB, threads=4, keyLen=32)`" + `
4. Decrypt using AES-256-GCM with the derived key and nonce
5. The decrypted plaintext is either:
   - a key JSON object containing the key type, public key (hex), and private key (hex), or
   - a backup bundle containing ` + "`backup_bundle`" + `, ` + "`payload_version`" + `, ` + "`key`" + `, and optional template fields (` + "`template_yaml`" + `, ` + "`template_type`" + `)

## Restoring Keys

### Using apstore (Recommended)

Import, preview, and apply through the local signer daemon:

` + "```bash" + `
apstore backup import /path/to/this/backup.tar.gz
apstore restore preview this-backup.tar.gz
apstore restore apply this-backup.tar.gz
` + "```" + `

Or apply only one address:

` + "```bash" + `
apstore restore apply this-backup.tar.gz --address <ADDRESS>
` + "```" + `

You will be prompted for the export passphrase used to encrypt the backup.
The running signer daemon encrypts restored keys into the target keystore. For
replacement-keystore rescue when no identity directory exists, use
` + "`apstore rebuild /path/to/this/backup.tar.gz`" + `, adding
` + "`--role attestor`" + ` when rebuilding an attestor node from a backup that
does not carry source role metadata.

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
