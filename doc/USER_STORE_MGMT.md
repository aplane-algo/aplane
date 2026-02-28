# Key Backup and Recovery Guide

This guide explains how to backup and restore your Falcon and Ed25519 keys.

## Table of Contents

- [Overview](#overview)
- [Backup Methods](#backup-methods)
- [Mnemonic Backup During Generation](#mnemonic-backup-during-generation)
- [Exporting Mnemonics from Existing Keys](#exporting-mnemonics-from-existing-keys)
- [File-Based Backup with apstore](#file-based-backup-with-apstore)
- [Keystore Management](#keystore-management)
- [Restoring Keys](#restoring-keys)
- [Security Best Practices](#security-best-practices)
- [Command Reference](#command-reference)
- [Troubleshooting](#troubleshooting)

---

## Overview

Signer uses **BIP-39 mnemonic phrases** for deterministic key generation:
- **Falcon keys**: 24-word mnemonic
- **Ed25519 keys**: 25-word mnemonic (Algorand standard)

These words are **all you need** to recreate your private keys on any device running Signer.

### Key Management Architecture

Key management is handled by **apadmin** and **apstore**, not directly by apsignerd:

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Management                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  apadmin (TUI)      ─────────►  Signer Server       │
│    • Generate keys                  • Signing only          │
│    • Import from mnemonic           • No key generation     │
│    • Export mnemonics               • Auto-loads new keys   │
│    • Delete keys                      via file watcher      │
│                                                             │
│  apadmin --batch    ─────────►  Signer Server       │
│    • Scripted key operations        (same connection)       │
│                                                             │
│  apstore           ─────────►  File System             │
│    • Initialize keystore           (direct file access)    │
│    • Backup/restore .key files                              │
│    • Change passphrase                                      │
│    • Inspect key contents                                   │
│    • Manage templates                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why BIP-39?

- **Human-readable**: Words are easier to write down than hex strings
- **Error detection**: Built-in checksum prevents typos
- **Deterministic**: Same words = same keys
- **Industry standard**: BIP-39 word format is widely recognized

**Important**: Falcon mnemonics use the BIP-39 word format but are **not cross-wallet compatible**. The Falcon-specific derivation means these mnemonics will not work in standard wallets. They only work with Signer and compatible Falcon tools.

---

## Backup Methods

Signer provides two complementary backup methods:

### 1. Mnemonic Backup (Recommended)

Write down the 24 or 25 words displayed during key generation. This is the most secure and portable backup method.

**Advantages:**
- Can restore keys on any device
- No file dependencies
- Human-readable and verifiable
- Works even if all devices are lost

### 2. File-Based Backup

Copy encrypted `.apb` files using the `apstore` tool.

**Advantages:**
- Faster restore (no derivation needed)
- Preserves all metadata
- Good for migrating between devices

**Best Practice:** Use both methods together - mnemonic for disaster recovery, file backup for convenience.

---

## Mnemonic Backup During Generation

Your mnemonic is displayed **once** during key generation via apadmin. Write it down immediately!

### Method 1: Generate via apadmin TUI (Recommended)

```bash
./apadmin
```

In the TUI:
1. Press `g` to generate a new key
2. Select key type (falcon1024-v1 or ed25519)
3. The mnemonic will be displayed on screen
4. **Write down all 24 words (Falcon) or 25 words (Ed25519)**
5. Press any key to continue (mnemonic is hidden after this)

### Method 2: Generate via Batch Mode

```bash
./apadmin --batch generate falcon1024-v1
./apadmin --batch generate ed25519
```

The mnemonic will be displayed in the console output.

**Note:** The mnemonic is only shown during generation. If you miss it, use the export command to retrieve it (see below).

### What to Write Down

For complete disaster recovery, record:

1. **BIP-39 Mnemonic** (required) - The 24 or 25 words
2. **Key Type** - Falcon or Ed25519
3. **Algorand Address** (optional) - To verify successful restoration
4. **Creation Date** (optional) - For your records

**Example backup note:**
```
Account: ABC123...XYZ789
Type: Falcon-1024
Created: 2025-01-15
Mnemonic: word1 word2 word3 ... word24
```

---

## Exporting Mnemonics from Existing Keys

If you lost your original mnemonic backup or need to export it again, use apadmin.

### Method 1: Export via apadmin TUI

```bash
./apadmin
```

In the TUI:
1. Select the key you want to export
2. Press `e` to export
3. Enter your passphrase when prompted
4. The mnemonic will be displayed
5. Write it down and press any key to hide

### Method 2: Export via Batch Mode

```bash
./apadmin --batch export <ADDRESS> [passphrase]
```

If passphrase is not provided, it uses the `TEST_PASSPHRASE` environment variable.

**Example:**
```bash
# With passphrase on command line
./apadmin --batch export ABC123...XYZ789 mysecretpassphrase

# Using environment variable
TEST_PASSPHRASE=mysecretpassphrase ./apadmin --batch export ABC123...XYZ789
```

### Export Compatibility

| Key Type | Export Available? |
|----------|-------------------|
| **Falcon** (with entropy) | Yes - full mnemonic export |
| **Falcon** (no entropy) | No - entropy not stored in older keys |
| **Ed25519** | Yes - always exportable (derived from private key) |

**Note:** Keys generated before entropy storage was implemented cannot export mnemonics. The key file itself is the backup for these older keys.

---

## File-Based Backup with apstore

For backing up encrypted key files directly (without needing to write down mnemonics), use the `apstore` CLI tool.

### Backup All Keys

```bash
./apstore backup all /mnt/usb/backup
```

This copies all keys from the keystore to the destination as `.apb` files, with checksums for verification.

### Backup Single Key

```bash
./apstore backup ABC123...XYZ789 /mnt/usb/backup
```

### Verify Backup

```bash
# Basic verification (file format check)
./apstore verify /mnt/usb/backup

# Deep verification (decrypt and validate keys)
./apstore verify /mnt/usb/backup --deep
```

### Backup Output

The backup includes:
- All `.apb` files (encrypted with export passphrase)
- `.keystore` metadata file (contains master salt for decryption)
- `README.md` with decryption instructions
- Checksums for integrity verification

**Important:** The backup uses the same master key encryption as your keystore. The `.keystore` file in the backup directory contains the master salt needed to decrypt the backup files.

---

## Keystore Management

### Initializing the Keystore

Before using apsignerd for the first time, you must initialize the keystore:

```bash
./apstore init
```

This creates the `.keystore` metadata file containing:
- Master salt for key derivation (Argon2id)
- Passphrase verification check

**Headless operation:** After initializing the keystore, configure `passphrase_command_argv` in your apsignerd `config.yaml` to provide the passphrase automatically at startup. See [USER_CONFIG.md](USER_CONFIG.md#headless-operation) for examples.

### Changing the Passphrase

To change your keystore passphrase:

```bash
./apstore changepass
```

This safely re-encrypts all keys and templates using a two-phase atomic operation:
1. **Phase 1**: Creates new encrypted files (`.new`) and verifies each one
2. **Phase 2**: Atomically swaps old files for new files

If any step fails, the operation is rolled back automatically.

### Listing Keys

To see all keys in your keystore:

```bash
./apstore keys
```

### Inspecting Key Files

To examine a key file's contents:

```bash
./apstore inspect ABC123...XYZ789
```

This shows:
- Encrypted envelope metadata (version, salt, nonce)
- Key type (ed25519, falcon1024-v1, etc.)
- Public key
- Address

**Show private key material (use with caution):**
```bash
./apstore inspect ABC123...XYZ789 --show-private
```

### Template Management

For custom LogicSig templates:

```bash
# List installed templates
./apstore templates

# Add a generic LogicSig template (TEAL-only, no keys)
./apstore add-template my-escrow-v1.yaml

# Add a Falcon-1024 DSA composition template (signature + TEAL suffix)
./apstore add-falcon-template falcon1024-hashlock-v2.yaml
```

Templates are encrypted and stored in the user directory's `templates/generic/` or `templates/falcon/` subdirectory.
They become available after unlocking apsignerd.

---

## Restoring Keys

### Scenario 1: Restore from Mnemonic (New Device)

Use apadmin to import your mnemonic:

**TUI Method:**
```bash
./apadmin
```
1. Press `i` to import a key
2. Select key type (falcon1024-v1 or ed25519)
3. Enter your 24 words (Falcon) or 25 words (Ed25519)
4. The key will be restored with the same address

**Batch Method:**
```bash
# Falcon key (24 words)
./apadmin --batch import falcon1024-v1 word1 word2 word3 ... word24

# Ed25519 key (25 words)
./apadmin --batch import ed25519 word1 word2 word3 ... word25
```

### Scenario 2: Restore from File Backup

Use apstore to restore encrypted key files:

```bash
./apstore restore all /mnt/usb/backup
```

The restore process:
1. If keystore exists: prompts for your **store passphrase** (to encrypt restored keys)
2. If no keystore: prompts you to create a new passphrase (with confirmation)
3. Prompts for your **backup passphrase** (to decrypt backup files from backup's `.keystore`)
4. Decrypts each key using the backup's master key
5. Re-encrypts keys with your store's master key and saves to keystore
6. apsignerd auto-detects new keys via file watching

**Note:** Backups include their own `.keystore` metadata file. The backup passphrase is the one used when the backup was created (which may differ from your current store passphrase).

**Restore Single Key:**
```bash
./apstore restore ABC123...XYZ789 /mnt/usb/backup
```

### Scenario 3: Restore Multiple Keys

You can restore multiple keys by running the import command multiple times:

```bash
# Restore first Falcon key
./apadmin --batch import falcon1024-v1 apple banana cherry ...

# Restore second Falcon key
./apadmin --batch import falcon1024-v1 zebra yellow xray ...

# Restore Ed25519 key
./apadmin --batch import ed25519 word1 word2 ... word25
```

### Verifying Restoration

After restoring, verify the address matches your backup:

```bash
./apadmin --batch list
```

The output should show your restored key with the expected address.

---

## Security Best Practices

### DO

- **Write down your mnemonic** immediately after generation
- **Store mnemonic offline** - Paper, metal backup, or encrypted password manager
- **Keep multiple copies** in separate secure locations
- **Test your backup** by doing a dry-run restoration on a test machine
- **Protect your encryption passphrase** - Required to decrypt key files

### DON'T

- **Never store mnemonic in plaintext** on internet-connected devices
- **Never share your mnemonic** - Anyone with these words controls your funds
- **Never email or message** your mnemonic to anyone
- **Never screenshot** your mnemonic (could sync to cloud)

### Physical Storage Recommendations

1. **Paper Backup** (minimum)
   - Write on acid-free paper (avoid thermal paper - it fades)
   - Use permanent ink
   - Store in waterproof container
   - Keep in safe or lockbox

2. **Metal Backup** (recommended for high-value keys)
   - Fireproof
   - Waterproof
   - Corrosion-resistant
   - Available: Cryptosteel, Billfodl, etc.

3. **Distributed Storage** (advanced)
   - Split into shares using Shamir's Secret Sharing (SSS)
   - Store shares in different locations
   - Require M-of-N shares to recover

### Encryption Passphrase Security

Your BIP-39 mnemonic generates the private key, but key files are **encrypted** with your store passphrase:

- Use a **strong, unique** passphrase (16+ characters)
- Store separately from mnemonic
- Required for:
  - Unlocking Signer
  - Exporting mnemonics
  - Restoring from file backups

**Important distinction:**
- **Mnemonic** → The source of your private key (permanent)
- **Encryption passphrase** → Protects the `.key` file (can be changed)

Without the encryption passphrase, you can still regenerate the same keys from your mnemonic.

---

## Command Reference

### apadmin TUI

| Key | Action |
|-----|--------|
| `g` | Generate new key |
| `i` | Import key from mnemonic |
| `e` | Export key's mnemonic |
| `d` | Delete key |
| `↑/↓` | Navigate key list |
| `q` | Quit |

### apadmin --batch

```bash
# List all keys
./apadmin --batch list

# Generate new key
./apadmin --batch generate falcon1024-v1
./apadmin --batch generate ed25519

# Import from mnemonic
./apadmin --batch import falcon1024-v1 word1 word2 ... word24
./apadmin --batch import ed25519 word1 word2 ... word25

# Export mnemonic
./apadmin --batch export <ADDRESS> [passphrase]

# Delete key
./apadmin --batch delete <ADDRESS>

# Unlock signer (uses TEST_PASSPHRASE env var)
./apadmin --batch unlock
```

### apstore

```bash
# Initialize keystore (required before first use)
./apstore init

# List keys in keystore
./apstore keys

# Inspect key file contents
./apstore inspect <ADDRESS>
./apstore inspect <keyfile.key> --show-private

# Backup keys
./apstore backup all <destination>
./apstore backup <ADDRESS> <destination>

# Restore keys
./apstore restore all <source>
./apstore restore <ADDRESS> <source>

# Verify backup
./apstore verify <backup-path>
./apstore verify <backup-path> --deep

# Change keystore passphrase
./apstore changepass

# Template management (for custom LogicSigs)
./apstore templates
./apstore add-template <yaml-file>              # Generic templates
./apstore add-falcon-template <yaml-file>       # Falcon DSA templates
```

---

## Troubleshooting

### "Invalid mnemonic" Error

**Problem**: BIP-39 validation failed

**Solutions**:
1. Check for typos in words
2. Verify you have exactly 24 words (Falcon) or 25 words (Ed25519)
3. Ensure words are from the BIP-39 wordlist
4. Check word order (order matters!)

### Different Address Generated

**Problem**: Restored address doesn't match backup

**Possible causes**:
1. Wrong mnemonic words or word order
2. Wrong key type (Falcon vs Ed25519)
3. Typo in one of the words

### "Key already exists" Error

**Problem**: Trying to restore a key that's already in the keystore

**Solution**:
1. Check if the key is already loaded: `./apadmin --batch list`
2. If you need to overwrite, delete the existing key first
3. Or restore to a fresh keystore directory

### "Signer is locked" Error

**Problem**: Signer is in locked state

**Solution**:
1. Connect with apadmin TUI to unlock
2. Or use batch mode: `TEST_PASSPHRASE=yourpassphrase ./apadmin --batch unlock`

### Cannot Export Mnemonic

**Problem**: "entropy not stored" error

**Cause**: The key was generated before entropy storage was implemented, or was created with a custom seed.

**Solution**:
- The `.key` file itself is your backup for these keys
- Use `apstore` to create file-based backups

---

## FAQ

**Q: Can I use my Algorand wallet mnemonic with Signer?**

A: Yes! For Ed25519 keys, import your 25-word Algorand mnemonic:
```bash
./apadmin --batch import ed25519 your 25 algorand words here
```

**Q: What if I forget my encryption passphrase?**

A: You can still use your mnemonic to regenerate the same address:
1. Import your mnemonic using apadmin
2. The same address will be regenerated
3. Set a new encryption passphrase
4. Delete the old encrypted files you can't access

**Q: Are Falcon BIP-39 mnemonics compatible with other wallets?**

A: No. Falcon key derivation is specific to Signer. Only Ed25519 mnemonics are compatible with Algorand wallets.

**Q: How do I backup multiple keys?**

A: Write down each mnemonic separately with its corresponding address:
```
Key 1 - Falcon
Address: ABC...
Mnemonic: word1 word2 ...

Key 2 - Ed25519
Address: XYZ...
Mnemonic: word1 word2 ...
```

Or use file-based backup:
```bash
./apstore backup all /mnt/usb/backup
```

**Q: Do I need entropy to use my keys?**

A: No! The `.key` file contains the actual private key, which is all you need for signing. Entropy is optional metadata that enables mnemonic export.

---

## Summary

| Aspect | Details |
|--------|---------|
| **Backup Format** | BIP-39 mnemonic (24 or 25 words) |
| **Falcon Keys** | 24 words |
| **Ed25519 Keys** | 25 words (Algorand compatible) |
| **Key Management Tool** | apadmin (TUI or --batch mode) |
| **Keystore Management** | apstore (init, keys, inspect, changepass) |
| **File Backup Tool** | apstore (backup, restore, verify) |
| **Encryption** | Argon2id key derivation + AES-256-GCM |
| **Storage** | Paper, metal, or distributed (Shamir SSS) |
| **Required for Recovery** | Mnemonic (+ key type) OR backup files + passphrase |

**Key Points:**
- Your BIP-39 mnemonic = complete key recovery
- Use apadmin for key generation, import, and export
- Use `apstore init` to initialize a new keystore before first use
- Use `apstore backup` for file-based backups (includes `.keystore` metadata)
- Use `apstore changepass` to safely change your passphrase
- The `.key` file works for signing with or without entropy metadata
- Mnemonic backup is portable; file backup is convenient

**Remember**: Your BIP-39 mnemonic is the **master key** to your funds. Treat it with the same security as cash. Anyone with these words can recreate your private keys and control your assets.
