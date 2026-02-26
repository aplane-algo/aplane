// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
	"github.com/aplane-algo/aplane/internal/version"
	falcon1024template "github.com/aplane-algo/aplane/lsig/falcon1024/v1/template"
	"github.com/aplane-algo/aplane/lsig/multitemplate"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"golang.org/x/term"
)

// Global config for commands that need it
var config util.ServerConfig

// stdinReader is a shared reader for non-terminal stdin
var stdinReader *bufio.Reader

func main() {
	// Handle early-exit flags before any other processing
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("apstore %s\n", version.String())
			os.Exit(0)
		}
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "apstore - Signer keystore management\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] init [--random]\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] backup <all|ADDRESS> <destination>\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] restore <all|ADDRESS> <source>\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] verify <backup-path> [--deep]\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] changepass [--random]\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] inspect <keyfile|ADDRESS> [--show-private]\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] keys\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] templates\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] add-template <yaml-file>\n")
		fmt.Fprintf(os.Stderr, "  apstore [-d path] add-falcon-template <yaml-file>\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -d path              Data directory (or set APSIGNER_DATA env var)\n")
		fmt.Fprintf(os.Stderr, "  --random             Generate random passphrase (init, changepass)\n")
		fmt.Fprintf(os.Stderr, "  --show-private       Show private key material (inspect only)\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  apstore init\n")
		fmt.Fprintf(os.Stderr, "  apstore init --random\n")
		fmt.Fprintf(os.Stderr, "  apstore backup all /mnt/usb/backup\n")
		fmt.Fprintf(os.Stderr, "  apstore backup ABC123... /mnt/usb/backup\n")
		fmt.Fprintf(os.Stderr, "  apstore restore all /mnt/usb/backup\n")
		fmt.Fprintf(os.Stderr, "  apstore restore ABC123... /mnt/usb/backup\n")
		fmt.Fprintf(os.Stderr, "  apstore verify /mnt/usb/backup --deep\n")
		fmt.Fprintf(os.Stderr, "  apstore changepass\n")
		fmt.Fprintf(os.Stderr, "  apstore changepass --random\n")
		fmt.Fprintf(os.Stderr, "  apstore inspect mykey.key\n")
		fmt.Fprintf(os.Stderr, "  apstore inspect ABC123... --show-private\n")
		fmt.Fprintf(os.Stderr, "  apstore keys\n")
		fmt.Fprintf(os.Stderr, "  apstore templates\n")
		fmt.Fprintf(os.Stderr, "  apstore add-template custom-escrow-v1.yaml\n")
		fmt.Fprintf(os.Stderr, "  apstore add-falcon-template falcon-multisig-v1.yaml\n")
	}

	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	flag.Parse()

	// Resolve data directory from -d flag or APSIGNER_DATA env var
	resolvedDataDir := util.RequireSignerDataDir(*dataDir)

	// Load config from data directory
	config = util.LoadServerConfig(resolvedDataDir)

	// Register all providers (must be called before using any registries)
	RegisterProviders()

	// Validate and set store path (must be done before any key operations)
	if config.StoreDir == "" {
		fmt.Fprintln(os.Stderr, "Error: store must be specified in config.yaml")
		fmt.Fprintln(os.Stderr, "Example: store: store")
		os.Exit(1)
	}
	utilkeys.SetKeystorePath(config.StoreDir)

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]

	switch command {
	case "init":
		random := len(args) > 1 && args[1] == "--random"
		if err := cmdInit(random); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "backup":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: apstore backup <all|ADDRESS> <destination>\n")
			os.Exit(1)
		}
		what := args[1]
		destination := args[2]
		if err := cmdBackup(what, destination); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "restore":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: apstore restore <all|ADDRESS> <source>\n")
			os.Exit(1)
		}
		what := args[1]
		source := args[2]
		if err := cmdRestore(what, source); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "verify":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: apstore verify <backup-path> [--deep]\n")
			os.Exit(1)
		}
		backupPath := args[1]
		deep := len(args) > 2 && args[2] == "--deep"
		if err := cmdVerify(backupPath, deep); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "changepass":
		random := len(args) > 1 && args[1] == "--random"
		if err := cmdChangepass(random); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "inspect":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: apstore inspect <keyfile|ADDRESS> [--show-private]\n")
			os.Exit(1)
		}
		target := args[1]
		showPrivate := len(args) > 2 && args[2] == "--show-private"
		if err := cmdInspect(target, showPrivate); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "keys":
		if err := cmdKeys(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "templates":
		if err := cmdTemplates(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "add-template":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: apstore add-template <yaml-file>\n")
			os.Exit(1)
		}
		if err := cmdAddTemplate(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "add-falcon-template":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: apstore add-falcon-template <yaml-file>\n")
			os.Exit(1)
		}
		if err := cmdAddFalconTemplate(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

// cmdBackup handles the backup command logic, delegating to all or single address backup.
func cmdBackup(what, destination string) error {
	// Check if destination directory exists
	info, err := os.Stat(destination)
	if os.IsNotExist(err) {
		return fmt.Errorf("destination directory does not exist: %s\n(Please create/mount the backup destination first)", destination)
	}
	if err != nil {
		return fmt.Errorf("cannot access destination: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("destination is not a directory: %s", destination)
	}

	// Prompt for store passphrase to decrypt keys from keystore
	fmt.Print("Enter store passphrase: ")
	storePassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()

	meta, err := crypto.LoadKeystoreMetadata(config.StoreDir)
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("keystore not initialized (missing .keystore file)")
	}

	masterKey, err := meta.VerifyAndDeriveMasterKey([]byte(storePassphrase))
	if err != nil {
		return fmt.Errorf("invalid store passphrase: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)
	fmt.Println("Store passphrase verified.")
	fmt.Println()

	// Prompt for export passphrase (with confirmation)
	fmt.Print("Enter export passphrase (for backup encryption): ")
	exportPassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read export passphrase: %w", err)
	}
	fmt.Println()

	if len(exportPassphrase) == 0 {
		return fmt.Errorf("export passphrase cannot be empty")
	}

	fmt.Print("Confirm export passphrase: ")
	confirmPassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	fmt.Println()

	if exportPassphrase != confirmPassphrase {
		return fmt.Errorf("export passphrases do not match")
	}
	fmt.Println()

	if what == "all" {
		return backupAll(destination, masterKey, []byte(exportPassphrase))
	}

	return backupAddress(what, destination, masterKey, []byte(exportPassphrase))
}

// backupAll performs a backup of all keys in the keystore to the destination.
func backupAll(destination string, masterKey, exportPassphrase []byte) error {
	fmt.Printf("Backing up all keys to %s\n\n", destination)

	checksums, err := backup.ExportAllKeys(utilkeys.KeysDir(auth.DefaultIdentityID), destination, masterKey, exportPassphrase)
	if err != nil {
		return err
	}

	// Write README.md to backup directory
	if err := backup.WriteReadme(destination); err != nil {
		fmt.Printf("Warning: Failed to write README.md: %v\n", err)
	}

	// Display results
	fmt.Printf("Successfully backed up %d key(s):\n", len(checksums))
	for address, checksum := range checksums {
		fmt.Printf("  %s.apb\n", address)
		fmt.Printf("    Checksum: %s\n", backup.FormatChecksum(checksum))
	}

	fmt.Printf("\nBackup complete! Files saved to: %s\n", destination)
	fmt.Printf("(README.md included with decryption instructions)\n")
	return nil
}

// backupAddress performs a backup of a single key to the destination.
func backupAddress(address, destination string, masterKey, exportPassphrase []byte) error {
	fmt.Printf("Backing up %s to %s\n\n", address, destination)

	// Create apb subdirectory to match backupAll layout
	keysDestDir := filepath.Join(destination, "apb")
	if err := os.MkdirAll(keysDestDir, 0750); err != nil {
		return fmt.Errorf("failed to create backup keys directory: %w", err)
	}

	checksum, size, err := backup.ExportKey(utilkeys.KeysDir(auth.DefaultIdentityID), keysDestDir, address, masterKey, exportPassphrase)
	if err != nil {
		return err
	}

	// Write README.md to backup directory
	if err := backup.WriteReadme(destination); err != nil {
		fmt.Printf("Warning: Failed to write README.md: %v\n", err)
	}

	fmt.Printf("%s.apb (%s)\n", address, backup.FormatFileSize(size))
	fmt.Printf("Checksum: %s\n", backup.FormatChecksum(checksum))
	fmt.Printf("\nBackup complete!\n")
	fmt.Printf("(README.md included with decryption instructions)\n")

	return nil
}

// cmdRestore handles the restore command logic, delegating to all or single address restore.
func cmdRestore(what, source string) error {
	// Check if source exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", source)
	}

	// Prompt for export passphrase (used to decrypt backup files)
	fmt.Print("Enter export passphrase (to decrypt backup files): ")
	exportPassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()

	// Get store passphrase and derive master key
	var masterKey []byte
	if crypto.KeystoreMetadataExistsIn(config.StoreDir) {
		fmt.Print("Enter store passphrase (to encrypt restored keys): ")
		storePassphrase, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		meta, err := crypto.LoadKeystoreMetadata(config.StoreDir)
		if err != nil {
			return fmt.Errorf("failed to load keystore metadata: %w", err)
		}

		masterKey, err = meta.VerifyAndDeriveMasterKey([]byte(storePassphrase))
		if err != nil {
			return fmt.Errorf("invalid store passphrase: %w", err)
		}
		fmt.Println("Store passphrase verified.")
	} else {
		fmt.Println("No store configured. Enter a passphrase to encrypt restored keys.")
		fmt.Print("Enter new store passphrase: ")
		storePassphrase, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		fmt.Print("Confirm passphrase: ")
		confirmPassphrase, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		if storePassphrase != confirmPassphrase {
			return fmt.Errorf("passphrases do not match")
		}

		// Create keystore metadata with new passphrase
		_, masterKey, err = crypto.CreateKeystoreMetadata(config.StoreDir, []byte(storePassphrase))
		if err != nil {
			return fmt.Errorf("failed to create keystore metadata: %w", err)
		}
		fmt.Println("Created new store encryption.")
	}
	defer crypto.ZeroBytes(masterKey)
	fmt.Println()

	if what == "all" {
		return restoreAll(source, masterKey, exportPassphrase)
	}

	return restoreAddress(what, source, masterKey, exportPassphrase)
}

// resolveBackupKeysDir returns the directory containing .apb files in a backup.
// Backup format uses an apb/ subdirectory.
func resolveBackupKeysDir(source string) string {
	return filepath.Join(source, "apb")
}

// restoreAll restores all keys from a backup source directory.
func restoreAll(source string, masterKey []byte, exportPassphrase string) error {
	fmt.Printf("Restoring all keys from %s\n\n", source)

	// Check for existing keys - warn user
	existingKeys, _ := backup.ScanKeyFiles(utilkeys.KeysDir(auth.DefaultIdentityID))
	if len(existingKeys) > 0 {
		fmt.Printf("Warning: %d key(s) already exist in %s directory\n", len(existingKeys), utilkeys.KeysDir(auth.DefaultIdentityID))
		fmt.Print("Existing keys will be overwritten. Continue? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "y" && response != "yes" {
			fmt.Println("Restore cancelled.")
			return nil
		}
		fmt.Println()
	}

	// Find where .apb files actually are (keys/ subdirectory or root)
	keysDir := resolveBackupKeysDir(source)

	// Scan backup directory for all keys to restore
	addresses, err := backup.ScanBackupFiles(keysDir)
	if err != nil {
		return err
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no .apb files found in backup: %s", source)
	}

	// Restore each key
	restored := 0
	for _, address := range addresses {
		keyType, err := restoreKey(keysDir, address, masterKey, exportPassphrase)
		if err != nil {
			fmt.Printf("Failed to restore %s: %v\n", address, err)
			continue
		}

		fmt.Printf("%s.apb", address)
		if keyType != "" {
			fmt.Printf(" (%s)", keyType)
		}
		fmt.Println()

		restored++
	}

	fmt.Printf("\nSuccessfully restored %d key(s) to %s\n", restored, utilkeys.KeysDir(auth.DefaultIdentityID))
	fmt.Println("\nNote: aplane will auto-detect the new keys")

	return nil
}

// restoreAddress restores a single key from a backup source.
func restoreAddress(address, source string, masterKey []byte, exportPassphrase string) error {
	fmt.Printf("Restoring %s from %s\n\n", address, source)

	// Check if key already exists
	destFile := utilkeys.KeyFilePath(auth.DefaultIdentityID, address)
	if _, err := os.Stat(destFile); err == nil {
		fmt.Printf("Warning: Key %s already exists\n", address)
		fmt.Print("Overwrite existing key? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "y" && response != "yes" {
			fmt.Println("Restore cancelled.")
			return nil
		}
		fmt.Println()
	}

	// Find where .apb files actually are
	keysDir := resolveBackupKeysDir(source)

	// Restore key
	keyType, err := restoreKey(keysDir, address, masterKey, exportPassphrase)
	if err != nil {
		return err
	}

	fmt.Printf("\n%s.apb restored", address)
	if keyType != "" {
		fmt.Printf(" (%s)", keyType)
	}
	fmt.Println()

	fmt.Println("\nNote: aplane will auto-detect the new key")

	return nil
}

// restoreKey handles the low-level logic of reading, decrypting, re-encrypting and saving a key file.
// keysDir is the directory containing .apb backup files. Backup files use standalone encryption
// (envelope_version 2) and are decrypted with the export passphrase. Restored files use
// master key encryption (envelope_version 1).
// Backup files may contain a BackupBundle (key + embedded template) or a plain KeyPair.
func restoreKey(keysDir, address string, masterKey []byte, exportPassphrase string) (string, error) {
	srcFile := filepath.Join(keysDir, address+".apb")

	// Read backup file
	data, err := os.ReadFile(srcFile)
	if err != nil {
		return "", fmt.Errorf("failed to read backup file: %w", err)
	}

	// Decrypt backup file if encrypted
	var decryptedData []byte
	if crypto.IsEncrypted(data) {
		// Check envelope version
		var envelope struct {
			EnvelopeVersion int `json:"envelope_version"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return "", fmt.Errorf("failed to parse backup file: %w", err)
		}

		switch envelope.EnvelopeVersion {
		case 2:
			// Standalone format — decrypt with export passphrase
			decryptedData, err = crypto.DecryptStandalone(data, []byte(exportPassphrase))
			if err != nil {
				return "", fmt.Errorf("failed to decrypt backup (wrong passphrase?): %w", err)
			}
		case 1:
			return "", fmt.Errorf("backup uses legacy format (envelope_version 1); re-export with current apstore")
		default:
			return "", fmt.Errorf("unsupported envelope_version: %d", envelope.EnvelopeVersion)
		}
	} else {
		// Unencrypted backup
		decryptedData = data
	}

	// Extract key JSON and optional embedded template from backup payload
	keyJSON, templateYAML, tmplType, err := backup.ParseBackup(decryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to parse backup payload: %w", err)
	}

	// Parse to get key type and address
	var keyData utilkeys.KeyPair
	if err := json.Unmarshal(keyJSON, &keyData); err != nil {
		return "", fmt.Errorf("failed to parse key file: %w", err)
	}

	// Verify the address matches the key data.
	// For DSA LogicSig keys with stored bytecode, derive the address from bytecode
	// (local computation, no algod needed). For other keys, use the address deriver.
	var derivedAddress string
	if keyData.LsigBytecodeHex != "" {
		bytecode, err := hex.DecodeString(keyData.LsigBytecodeHex)
		if err != nil {
			return "", fmt.Errorf("failed to decode lsig bytecode: %w", err)
		}
		lsig := sdkcrypto.LogicSigAccount{
			Lsig: types.LogicSig{Logic: bytecode},
		}
		addr, err := lsig.Address()
		if err != nil {
			return "", fmt.Errorf("failed to derive address from bytecode: %w", err)
		}
		derivedAddress = addr.String()
	} else {
		deriver, err := util.GetAddressDeriver(keyData.KeyType)
		if err != nil {
			return "", fmt.Errorf("unsupported key type: %s", keyData.KeyType)
		}
		derivedAddress, err = deriver.DeriveAddress(keyData.PublicKeyHex, keyData.Params)
		if err != nil {
			return "", fmt.Errorf("failed to derive address: %w", err)
		}
	}

	if derivedAddress != address {
		return "", fmt.Errorf("address mismatch: expected %s, got %s", address, derivedAddress)
	}

	// Encrypt key JSON (not the bundle) with master key
	encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Write to keys directory
	destPath := utilkeys.KeyFilePath(auth.DefaultIdentityID, address)

	// Ensure keys subdirectory exists
	if err := os.MkdirAll(utilkeys.KeysDir(auth.DefaultIdentityID), 0770); err != nil {
		return "", fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Write the file
	if err := os.WriteFile(destPath, encrypted, 0660); err != nil {
		return "", fmt.Errorf("failed to write key file: %w", err)
	}

	// Restore embedded template if present in backup bundle
	if templateYAML != nil {
		if err := restoreTemplate(templateYAML, keyData.KeyType, tmplType, masterKey); err != nil {
			return "", fmt.Errorf("failed to restore template for %s: %w", address, err)
		}
	}

	return keyData.KeyType, nil
}

// restoreTemplate saves a template extracted from a backup bundle to the keystore.
// templateYAML is the raw YAML content, keyType identifies the key, and
// tmplType is "falcon" or "generic" (from the bundle's template_type field).
func restoreTemplate(templateYAML []byte, keyType, tmplType string, masterKey []byte) error {
	tt := templatestore.TemplateTypeGeneric
	if tmplType == "falcon" {
		tt = templatestore.TemplateTypeFalcon
	}

	// Skip if template already exists
	if templatestore.TemplateExists(keyType, tt) {
		return nil
	}

	// Save template encrypted with master key
	if _, err := templatestore.SaveTemplate(templateYAML, keyType, tt, masterKey); err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	fmt.Printf("  Restored template: %s (%s)\n", keyType, tt)
	return nil
}

// cmdVerify handles the verify command logic, dispatching to basic or deep verification.
func cmdVerify(backupPath string, deep bool) error {
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupPath)
	}

	if deep {
		return verifyDeep(backupPath)
	}

	return verifyBasic(backupPath)
}

// verifyBasic performs a structural check of the backup files without decrypting them.
func verifyBasic(backupPath string) error {
	fmt.Printf("Scanning %s...\n", backupPath)

	report, err := backup.VerifyBackup(backupPath)
	if err != nil {
		return err
	}

	fmt.Printf("Found %d key file(s):\n\n", report.TotalFiles)

	for _, result := range report.Results {
		if result.Valid {
			fmt.Printf("  %s (%s, valid format)\n", result.FileName, backup.FormatFileSize(result.Size))
		} else {
			fmt.Printf("  %s - %s\n", result.FileName, result.Error)
		}
	}

	fmt.Println()
	if report.FailedFiles == 0 {
		fmt.Println("All files passed basic validation")
	} else {
		fmt.Printf("%d file(s) failed validation\n", report.FailedFiles)
	}

	return nil
}

// verifyDeep performs a full verification including decryption of all keys.
func verifyDeep(backupPath string) error {
	fmt.Println("Deep verification requires passphrase to decrypt keys")
	fmt.Print("Enter passphrase: ")

	passphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()

	fmt.Printf("Verifying %s...\n", backupPath)

	report, err := backup.DeepVerifyBackup(backupPath, passphrase)
	if err != nil {
		return err
	}

	fmt.Printf("Found %d key file(s):\n\n", report.TotalFiles)

	for _, result := range report.Results {
		if result.Valid {
			fmt.Printf("  %s (%s, decrypts OK)\n", result.FileName, result.KeyType)
		} else {
			fmt.Printf("  %s - %s\n", result.FileName, result.Error)
		}
	}

	fmt.Println()
	if report.FailedFiles == 0 {
		fmt.Println("All keys valid and decryptable")
	} else {
		fmt.Printf("%d file(s) failed validation\n", report.FailedFiles)
	}

	return nil
}

// readPassword safely reads a password from stdin, handling both terminal and non-terminal inputs.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 - file descriptors are small integers
	if term.IsTerminal(fd) {
		bytePassword, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		return string(bytePassword), nil
	}

	// Not a terminal - read plaintext line using shared reader
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// cmdChangepass changes the store passphrase using a safe write-new-then-rename pattern
func cmdChangepass(random bool) error {
	// Check if keystore metadata exists
	keystorePath := filepath.Join(config.StoreDir, ".keystore")
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		return fmt.Errorf("no .keystore file found in %s - store not initialized", config.StoreDir)
	}

	fmt.Println("Signer Passphrase Change Utility")
	fmt.Println("=====================================")
	fmt.Println()

	// Determine if we're using the passphrase command helper
	useHelper := len(config.PassphraseCommandArgv) > 0

	// Get old passphrase
	var oldPassphrase string
	if useHelper {
		// Read current passphrase via helper command
		cmdCfg := config.PassphraseCommandCfg()
		cmdCfg.Verb = "read"
		oldBytes, err := util.RunPassphraseCommand(cmdCfg, nil)
		if err != nil {
			return fmt.Errorf("failed to read current passphrase via helper: %w", err)
		}
		oldPassphrase = string(oldBytes)
		crypto.ZeroBytes(oldBytes)
		fmt.Println("Current passphrase read via passphrase command helper.")
	} else {
		fmt.Print("Enter current passphrase: ")
		var err error
		oldPassphrase, err = readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()
	}

	// Load metadata and verify old passphrase
	oldMeta, err := crypto.LoadKeystoreMetadata(config.StoreDir)
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	oldMasterKey, err := oldMeta.VerifyAndDeriveMasterKey([]byte(oldPassphrase))
	if err != nil {
		return fmt.Errorf("current passphrase verification failed: %w", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)
	fmt.Println("Current passphrase verified.")
	fmt.Println()

	// Get new passphrase
	var newPassphrase string
	if random {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to generate random passphrase: %w", err)
		}
		newPassphrase = base64.StdEncoding.EncodeToString(randomBytes)
		if useHelper {
			fmt.Println("Generated random passphrase (will be stored via helper).")
		} else {
			fmt.Printf("Generated new passphrase: %s\n", newPassphrase)
			fmt.Println("\nIMPORTANT: Save this passphrase securely!")
			fmt.Println("SECURITY: Clear shell history after copying this passphrase.")
		}
		fmt.Println()
	} else {
		fmt.Print("Enter new passphrase: ")
		newPassphrase, err = readPassword()
		if err != nil {
			return fmt.Errorf("failed to read new passphrase: %w", err)
		}
		fmt.Println()

		if len(newPassphrase) == 0 {
			return fmt.Errorf("new passphrase cannot be empty")
		}

		fmt.Print("Confirm new passphrase: ")
		confirm, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		fmt.Println()

		if newPassphrase != confirm {
			return fmt.Errorf("passphrases do not match")
		}
	}

	if newPassphrase == oldPassphrase {
		return fmt.Errorf("new passphrase must be different from current passphrase")
	}

	// Scan for key files in the keys subdirectory
	addresses, err := backup.ScanKeyFiles(utilkeys.KeysDir(auth.DefaultIdentityID))
	if err != nil {
		return fmt.Errorf("failed to scan keystore: %w", err)
	}

	// Scan for template files in all template subdirectories
	var templateFiles []string
	templatesRootDir := utilkeys.TemplatesRootDir()
	_ = filepath.WalkDir(templatesRootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".template") {
			templateFiles = append(templateFiles, path)
		}
		return nil
	})

	if len(addresses) == 0 && len(templateFiles) == 0 {
		fmt.Println("No key or template files found in keystore.")
	} else {
		if len(addresses) > 0 {
			fmt.Printf("Found %d key file(s) to migrate.\n", len(addresses))
		}
		if len(templateFiles) > 0 {
			fmt.Printf("Found %d template file(s) to migrate.\n", len(templateFiles))
		}
	}
	fmt.Println()

	// Confirm (skip in fully automated mode: helper + random)
	if !useHelper || !random {
		fmt.Print("Proceed with passphrase change? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
		fmt.Println()
	}

	// Track files for atomic swap
	type pendingFile struct {
		original string
		newPath  string
		oldPath  string
	}
	var pendingFiles []pendingFile

	// Cleanup function for phase 1 failures (remove .new files)
	cleanupNew := func() {
		for _, pf := range pendingFiles {
			_ = os.Remove(pf.newPath) // Best-effort cleanup
		}
	}

	// Rollback function for phase 2 failures (restore from .old files)
	rollback := func() {
		fmt.Println("\nRolling back changes...")
		for _, pf := range pendingFiles {
			// If .old exists, restore it
			if _, err := os.Stat(pf.oldPath); err == nil {
				if err := os.Rename(pf.oldPath, pf.original); err != nil {
					fmt.Fprintf(os.Stderr, "  Failed to restore %s: %v\n", pf.original, err)
				} else {
					fmt.Printf("  Restored: %s\n", filepath.Base(pf.original))
				}
			}
			// Clean up any .new files
			_ = os.Remove(pf.newPath) // Best-effort cleanup
		}
	}

	// Cleanup function for success (remove .old files)
	cleanupOld := func() {
		for _, pf := range pendingFiles {
			_ = os.Remove(pf.oldPath) // Best-effort cleanup
		}
	}

	// Create new keystore metadata (generates new salt and derives new master key)
	newKeystorePath := keystorePath + ".new"
	oldKeystorePath := keystorePath + ".old"

	newMeta, newMasterKey, err := crypto.CreateKeystoreMetadataTemp([]byte(newPassphrase))
	if err != nil {
		return fmt.Errorf("failed to create new keystore metadata: %w", err)
	}
	defer crypto.ZeroBytes(newMasterKey)

	// ========================================
	// PHASE 1: Create and verify all new files
	// ========================================
	fmt.Println("Phase 1: Creating new encrypted files...")

	// 1a. Re-encrypt all key files to .new
	for _, address := range addresses {
		keyPath := utilkeys.KeyFilePath(auth.DefaultIdentityID, address)
		newPath := keyPath + ".new"
		oldPath := keyPath + ".old"

		// Read current file
		data, err := os.ReadFile(keyPath)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to read %s: %w", address, err)
		}

		// Check if encrypted
		if !crypto.IsEncrypted(data) {
			fmt.Printf("  Skipping %s (not encrypted)\n", address)
			continue
		}

		// Decrypt with old master key
		plaintext, err := crypto.DecryptWithMasterKey(data, oldMasterKey)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to decrypt %s: %w", address, err)
		}

		// Re-encrypt with new master key
		newData, err := crypto.EncryptWithMasterKey(plaintext, newMasterKey)
		crypto.ZeroBytes(plaintext)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to re-encrypt %s: %w", address, err)
		}

		// Write to .new file
		if err := os.WriteFile(newPath, newData, 0660); err != nil {
			cleanupNew()
			return fmt.Errorf("failed to write %s.new: %w", address, err)
		}

		// Verify .new file can be decrypted
		verifyData, err := os.ReadFile(newPath)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to verify %s.new: %w", address, err)
		}
		if _, err := crypto.DecryptWithMasterKey(verifyData, newMasterKey); err != nil {
			cleanupNew()
			return fmt.Errorf("verification failed for %s.new: %w", address, err)
		}

		pendingFiles = append(pendingFiles, pendingFile{keyPath, newPath, oldPath})
		fmt.Printf("  Created: %s.new (verified)\n", address)
	}

	// 1b. Re-encrypt all template files to .new
	for _, templatePath := range templateFiles {
		templateName := filepath.Base(templatePath)
		newPath := templatePath + ".new"
		oldPath := templatePath + ".old"

		// Read current file
		data, err := os.ReadFile(templatePath)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to read template %s: %w", templateName, err)
		}

		// Check if encrypted
		if !crypto.IsEncrypted(data) {
			fmt.Printf("  Skipping template %s (not encrypted)\n", templateName)
			continue
		}

		// Decrypt with old master key
		plaintext, err := crypto.DecryptWithMasterKey(data, oldMasterKey)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to decrypt template %s: %w", templateName, err)
		}

		// Re-encrypt with new master key
		newData, err := crypto.EncryptWithMasterKey(plaintext, newMasterKey)
		crypto.ZeroBytes(plaintext)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to re-encrypt template %s: %w", templateName, err)
		}

		// Write to .new file
		if err := os.WriteFile(newPath, newData, 0660); err != nil {
			cleanupNew()
			return fmt.Errorf("failed to write %s.new: %w", templateName, err)
		}

		// Verify .new file can be decrypted
		verifyData, err := os.ReadFile(newPath)
		if err != nil {
			cleanupNew()
			return fmt.Errorf("failed to verify %s.new: %w", templateName, err)
		}
		if _, err := crypto.DecryptWithMasterKey(verifyData, newMasterKey); err != nil {
			cleanupNew()
			return fmt.Errorf("verification failed for %s.new: %w", templateName, err)
		}

		pendingFiles = append(pendingFiles, pendingFile{templatePath, newPath, oldPath})
		fmt.Printf("  Created: %s.new (verified)\n", templateName)
	}

	// 1c. Write new keystore metadata
	newMetaData, err := json.MarshalIndent(newMeta, "", "  ")
	if err != nil {
		cleanupNew()
		return fmt.Errorf("failed to marshal new keystore metadata: %w", err)
	}

	if err := os.WriteFile(newKeystorePath, newMetaData, 0660); err != nil {
		cleanupNew()
		return fmt.Errorf("failed to write .keystore.new: %w", err)
	}

	// Verify keystore metadata
	verifyMeta, err := crypto.LoadKeystoreMetadataFrom(newKeystorePath)
	if err != nil {
		cleanupNew()
		return fmt.Errorf("failed to verify .keystore.new: %w", err)
	}
	if _, err := verifyMeta.VerifyAndDeriveMasterKey([]byte(newPassphrase)); err != nil {
		cleanupNew()
		return fmt.Errorf("verification failed for .keystore.new")
	}

	pendingFiles = append(pendingFiles, pendingFile{keystorePath, newKeystorePath, oldKeystorePath})
	fmt.Println("  Created: .keystore.new (verified)")

	// ========================================
	// PHASE 2: Atomic swap (rename operations)
	// ========================================
	fmt.Println("\nPhase 2: Atomic file swap...")

	for i, pf := range pendingFiles {
		// Move original to .old (atomic backup)
		if _, err := os.Stat(pf.original); err == nil {
			if err := os.Rename(pf.original, pf.oldPath); err != nil {
				// Rollback any already-swapped files
				pendingFiles = pendingFiles[:i]
				rollback()
				return fmt.Errorf("failed to backup %s: %w", filepath.Base(pf.original), err)
			}
		}

		// Move .new to original (atomic install)
		if err := os.Rename(pf.newPath, pf.original); err != nil {
			// Try to restore this file's .old (best effort)
			_ = os.Rename(pf.oldPath, pf.original)
			// Rollback already-swapped files
			pendingFiles = pendingFiles[:i]
			rollback()
			return fmt.Errorf("failed to install %s: %w", filepath.Base(pf.original), err)
		}

		fmt.Printf("  Swapped: %s\n", filepath.Base(pf.original))
	}

	// ========================================
	// PHASE 2b: Store new passphrase via helper (if configured)
	// ========================================
	if useHelper {
		if err := util.WritePassphrase(config.PassphraseCommandCfg(), []byte(newPassphrase)); err != nil {
			fmt.Fprintf(os.Stderr, "\nError: failed to store new passphrase via helper: %v\n", err)
			fmt.Fprintln(os.Stderr, "Rolling back keystore to previous passphrase...")
			rollback()
			return fmt.Errorf("passphrase change aborted: helper write failed")
		}
		fmt.Println("  Stored new passphrase via passphrase command helper.")
	}

	// ========================================
	// PHASE 3: Cleanup .old files
	// ========================================
	cleanupOld()

	fmt.Println()
	fmt.Println("Passphrase change complete!")
	if len(addresses) > 0 {
		fmt.Printf("  - %d key file(s) migrated\n", len(addresses))
	}
	if len(templateFiles) > 0 {
		fmt.Printf("  - %d template file(s) migrated\n", len(templateFiles))
	}
	fmt.Println("  - Keystore metadata updated")

	return nil
}

// cmdInit initializes a new keystore with a passphrase.
// If random is true, generates a random passphrase instead of prompting.
// When a passphrase_command_argv helper is configured, the passphrase is
// stored via the helper after keystore creation.
func cmdInit(random bool) error {
	fmt.Println("Keystore Initialization")
	fmt.Println("=======================")
	fmt.Println()

	// Check if control file already exists
	if crypto.KeystoreMetadataExistsIn(config.StoreDir) {
		return fmt.Errorf("keystore already initialized (control file exists in %s)", config.StoreDir)
	}

	// Ensure store directory exists with setgid so files inherit the group
	if err := os.MkdirAll(config.StoreDir, 0770); err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}
	if err := os.Chmod(config.StoreDir, os.ModeSetgid|0770); err != nil {
		return fmt.Errorf("failed to set permissions on keystore directory: %w", err)
	}

	fmt.Printf("Keystore directory: %s\n", config.StoreDir)
	fmt.Println()

	useHelper := len(config.PassphraseCommandArgv) > 0

	// Get passphrase
	var passphrase string
	if random {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to generate random passphrase: %w", err)
		}
		passphrase = base64.StdEncoding.EncodeToString(randomBytes)
		if useHelper {
			fmt.Println("Generated random passphrase (will be stored via helper).")
		} else {
			fmt.Printf("Generated passphrase: %s\n", passphrase)
			fmt.Println("\nIMPORTANT: Save this passphrase securely!")
			fmt.Println("SECURITY: Clear shell history after copying this passphrase.")
		}
	} else {
		fmt.Println("Choose a strong passphrase. This will be used to encrypt all keys.")
		fmt.Println("You will need this passphrase to unlock the signer.")
		fmt.Println()

		fmt.Print("Enter passphrase: ")
		var err error
		passphrase, err = readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		if len(passphrase) == 0 {
			return fmt.Errorf("passphrase cannot be empty")
		}

		// Confirm passphrase
		fmt.Print("Confirm passphrase: ")
		confirm, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		fmt.Println()

		if passphrase != confirm {
			return fmt.Errorf("passphrases do not match")
		}
	}

	// Create keystore metadata
	_, masterKey, err := crypto.CreateKeystoreMetadata(config.StoreDir, []byte(passphrase))
	if err != nil {
		return fmt.Errorf("failed to create keystore metadata: %w", err)
	}
	crypto.ZeroBytes(masterKey)

	// Create identity-scoped keys directory
	if err := os.MkdirAll(utilkeys.KeysDir(auth.DefaultIdentityID), 0770); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Keystore initialized successfully!")
	fmt.Printf("  Keystore metadata: %s/.keystore\n", config.StoreDir)
	fmt.Println()

	// If passphrase_command_argv is configured, store the passphrase via the helper
	if useHelper {
		if err := util.WritePassphrase(config.PassphraseCommandCfg(), []byte(passphrase)); err != nil {
			fmt.Println("⚠️  Could not store passphrase via passphrase command helper:")
			fmt.Printf("   %v\n", err)
			fmt.Println("   Store the passphrase manually in your secrets backend.")
		} else {
			fmt.Println("✓ Passphrase stored via passphrase command helper.")
		}
		fmt.Println()
	}

	fmt.Println("You can now start apsignerd and use apadmin to unlock.")
	if !useHelper {
		fmt.Println("For headless operation, configure passphrase_command_argv in config.yaml.")
	}

	return nil
}

// cmdInspect displays the contents of an encrypted key file
func cmdInspect(target string, showPrivate bool) error {
	// Resolve target to a key file path
	var keyFile string
	if strings.HasSuffix(target, ".key") || strings.HasSuffix(target, ".apb") {
		// Direct file path
		if filepath.IsAbs(target) {
			keyFile = target
		} else {
			keyFile = filepath.Join(config.StoreDir, target)
		}
	} else {
		// Assume it's an address - look for matching key file
		keyFile = utilkeys.KeyFilePath(auth.DefaultIdentityID, target)
	}

	// Check if file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", keyFile)
	}

	fmt.Printf("Key File: %s\n", keyFile)
	fmt.Println(strings.Repeat("=", 60))

	// Read encrypted file
	encryptedData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Parse encrypted envelope to show version
	var envelope crypto.EncryptedData
	if err := json.Unmarshal(encryptedData, &envelope); err != nil {
		return fmt.Errorf("failed to parse encrypted envelope: %w", err)
	}

	fmt.Printf("\nEncrypted Envelope:\n")
	fmt.Printf("  Envelope Version: %d\n", envelope.EnvelopeVersion)
	fmt.Printf("  Salt:       %s (%d bytes)\n", truncateString(envelope.Salt, 16), len(envelope.Salt))
	fmt.Printf("  Nonce:      %s (%d bytes)\n", truncateString(envelope.Nonce, 16), len(envelope.Nonce))
	fmt.Printf("  Ciphertext: %d bytes\n", len(envelope.Ciphertext))

	// Decrypt based on envelope version
	var decrypted []byte
	if envelope.EnvelopeVersion == 2 {
		// Standalone format — decrypt with passphrase directly
		fmt.Print("\nEnter passphrase to decrypt: ")
		passphrase, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		decrypted, err = crypto.DecryptStandalone(encryptedData, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
	} else {
		// Master key format — decrypt via keystore
		fmt.Print("\nEnter passphrase to decrypt: ")
		passphrase, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		meta, err := crypto.LoadKeystoreMetadata(config.StoreDir)
		if err != nil {
			return fmt.Errorf("failed to load keystore metadata: %w", err)
		}
		if meta == nil {
			return fmt.Errorf("keystore not initialized (missing .keystore file)")
		}

		masterKey, err := meta.VerifyAndDeriveMasterKey([]byte(passphrase))
		if err != nil {
			return fmt.Errorf("invalid passphrase: %w", err)
		}
		defer crypto.ZeroBytes(masterKey)

		decrypted, err = crypto.DecryptWithMasterKey(encryptedData, masterKey)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
	}
	defer crypto.ZeroBytes(decrypted)

	// Detect backup bundle (key + embedded template) vs plain KeyPair
	keyJSON, templateYAML, tmplType, err := backup.ParseBackup(decrypted)
	if err != nil {
		return fmt.Errorf("failed to parse decrypted data: %w", err)
	}

	if templateYAML != nil {
		fmt.Printf("\nBackup Bundle: yes (embedded %s template)\n", tmplType)
	}

	// Pretty-print the key JSON
	var prettyJSON map[string]interface{}
	if err := json.Unmarshal(keyJSON, &prettyJSON); err != nil {
		return fmt.Errorf("failed to parse key data: %w", err)
	}

	fmt.Printf("\nDecrypted Contents:\n")

	// Check for format version
	if formatVersion, ok := prettyJSON["format_version"].(float64); ok {
		fmt.Printf("  Format Version: %d\n", int(formatVersion))
	}

	// Check for key type
	if keyType, ok := prettyJSON["key_type"].(string); ok {
		fmt.Printf("  Key Type:   %s\n", keyType)
	}

	// Check for category (LogicSig)
	if category, ok := prettyJSON["category"].(string); ok {
		fmt.Printf("  Category:   %s\n", category)
	}

	// Check for address
	if address, ok := prettyJSON["address"].(string); ok {
		fmt.Printf("  Address:    %s\n", address)
	}

	// Check for template (LogicSig)
	if template, ok := prettyJSON["template"].(string); ok {
		fmt.Printf("  Template:   %s\n", template)
	}

	// Check for parameters (LogicSig)
	if params, ok := prettyJSON["parameters"].(map[string]interface{}); ok && len(params) > 0 {
		fmt.Printf("  Parameters:\n")
		for k, v := range params {
			fmt.Printf("    %s: %v\n", k, v)
		}
	}

	// Check for public key
	if pubKey, ok := prettyJSON["public_key"].(string); ok {
		fmt.Printf("  Public Key: %s... (%d chars)\n", pubKey[:min(32, len(pubKey))], len(pubKey))
	}

	// Check for private key
	if privKey, ok := prettyJSON["private_key"].(string); ok {
		if showPrivate {
			fmt.Printf("  Private Key: %s\n", privKey)
		} else {
			fmt.Printf("  Private Key: [REDACTED] (%d chars) - use --show-private to display\n", len(privKey))
		}
	}

	// Check for bytecode (LogicSig) - supports both field names
	bytecodeHex := ""
	if bc, ok := prettyJSON["bytecode_hex"].(string); ok {
		bytecodeHex = bc
	} else if bc, ok := prettyJSON["lsig_bytecode"].(string); ok {
		bytecodeHex = bc
	}
	if bytecodeHex != "" {
		fmt.Printf("  Bytecode:   %d bytes (hex)\n", len(bytecodeHex)/2)
	}

	fmt.Println()
	return nil
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// truncateString safely truncates a string to maxLen characters, adding "..." if truncated.
// Returns the full string if shorter than maxLen.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// cmdKeys lists all key files in the keystore directory
func cmdKeys() error {
	keysDir := utilkeys.KeysDir(auth.DefaultIdentityID)
	fmt.Printf("Keystore: %s\n", config.StoreDir)
	fmt.Printf("Keys directory: %s\n", keysDir)
	fmt.Println(strings.Repeat("=", 60))

	// Check if directory exists
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		fmt.Println("\nNo keys directory found (no keys generated yet).")
		return nil
	}

	// Read directory
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}

	// Filter and list key files
	var keyFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".key") {
			keyFiles = append(keyFiles, entry)
		}
	}

	if len(keyFiles) == 0 {
		fmt.Println("\nNo key files found.")
		return nil
	}

	fmt.Printf("\nFound %d key file(s):\n\n", len(keyFiles))

	for _, entry := range keyFiles {
		info, err := entry.Info()
		if err != nil {
			fmt.Printf("  %s (error reading info: %v)\n", entry.Name(), err)
			continue
		}

		// Read file to get version from encrypted envelope
		keyPath := filepath.Join(keysDir, entry.Name())
		encData, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Printf("  %s  %8d bytes  (error reading: %v)\n", entry.Name(), info.Size(), err)
			continue
		}

		var envelope crypto.EncryptedData
		version := "?"
		if err := json.Unmarshal(encData, &envelope); err == nil {
			version = fmt.Sprintf("%d", envelope.EnvelopeVersion)
		}

		fmt.Printf("  %s  (%d bytes, v%s)\n", entry.Name(), info.Size(), version)
	}

	fmt.Println()
	fmt.Println("Use 'apstore inspect <file>' to view details.")
	return nil
}

// cmdTemplates lists all template files in the keystore templates directories
func cmdTemplates() error {
	fmt.Printf("Keystore: %s\n", config.StoreDir)
	fmt.Println(strings.Repeat("=", 60))

	type templateEntry struct {
		keyType      string
		size         int64
		templateType string
	}

	var allTemplates []templateEntry

	// Scan all template subdirectories
	_ = filepath.WalkDir(utilkeys.TemplatesRootDir(), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".template") {
			info, _ := d.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			allTemplates = append(allTemplates, templateEntry{
				keyType:      strings.TrimSuffix(d.Name(), ".template"),
				size:         size,
				templateType: filepath.Base(filepath.Dir(path)),
			})
		}
		return nil
	})

	if len(allTemplates) == 0 {
		fmt.Println("\nNo template files found.")
		return nil
	}

	fmt.Printf("\nFound %d template file(s):\n\n", len(allTemplates))

	for _, t := range allTemplates {
		fmt.Printf("  %s  (%d bytes, %s)\n", t.keyType, t.size, t.templateType)
	}

	fmt.Println()
	fmt.Println("Use 'apstore add-template' or 'apstore add-falcon-template' to add new templates.")
	return nil
}

// cmdAddTemplate encrypts a YAML template file and stores it in the keystore.
// The template will be loaded and registered when apsignerd unlocks.
func cmdAddTemplate(yamlPath string) error {
	// Check if keystore is initialized
	if !crypto.KeystoreMetadataExistsIn(utilkeys.KeystorePath()) {
		return fmt.Errorf("keystore not initialized, run 'apstore init' first")
	}

	// Read the YAML file
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}

	// Parse the template to validate and get keyType
	spec, err := multitemplate.ParseTemplateSpec(data)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Validate the template
	if err := multitemplate.ValidateSpec(spec); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	// Compute keyType from family and version
	keyType := fmt.Sprintf("%s-v%d", spec.Family, spec.Version)

	// Check if template already exists in either template directory (generic or falcon)
	if templatestore.TemplateExists(keyType, templatestore.TemplateTypeGeneric) {
		return fmt.Errorf("template %s already exists in templates directory", keyType)
	}
	if templatestore.TemplateExists(keyType, templatestore.TemplateTypeFalcon) {
		return fmt.Errorf("key type %s already exists as a falcon template", keyType)
	}

	// Check for collision with any registered provider (built-in)
	if lsigprovider.Has(keyType) {
		return fmt.Errorf("key type %s is already registered as a built-in provider", keyType)
	}

	// Prompt for passphrase
	fmt.Print("Enter passphrase: ")
	passphraseStr, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()

	// Load keystore metadata and derive master key
	meta, err := crypto.LoadKeystoreMetadata(utilkeys.KeystorePath())
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("keystore not initialized (missing .keystore file)")
	}

	masterKey, err := meta.VerifyAndDeriveMasterKey([]byte(passphraseStr))
	if err != nil {
		return fmt.Errorf("invalid passphrase: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)

	// Save the template using the common templatestore
	outputPath, err := templatestore.SaveTemplate(data, keyType, templatestore.TemplateTypeGeneric, masterKey)
	if err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	fmt.Printf("✓ Template %s added successfully\n", keyType)
	fmt.Printf("  File: %s\n", outputPath)
	fmt.Printf("  Family: %s\n", spec.Family)
	fmt.Printf("  Version: %d\n", spec.Version)
	fmt.Printf("  Display name: %s\n", spec.DisplayName)
	fmt.Println("\nThe template will be available after unlocking apsignerd.")
	return nil
}

// cmdAddFalconTemplate encrypts a Falcon YAML template and stores it in the keystore.
// Falcon templates define DSA compositions using parameterized TEAL suffixes.
// The template will be loaded and registered when apsignerd unlocks.
func cmdAddFalconTemplate(yamlPath string) error {
	// Check if keystore is initialized
	if !crypto.KeystoreMetadataExistsIn(utilkeys.KeystorePath()) {
		return fmt.Errorf("keystore not initialized, run 'apstore init' first")
	}

	// Read the YAML file
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}

	// Parse the template to validate and get keyType
	spec, err := falcon1024template.ParseTemplateSpec(data)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Validate the template (checks constraints exist, etc.)
	if err := falcon1024template.ValidateSpec(spec); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	keyType := spec.KeyType()

	// Check if template already exists in either template directory (falcon or generic)
	if templatestore.TemplateExists(keyType, templatestore.TemplateTypeFalcon) {
		return fmt.Errorf("falcon template %s already exists in falcon-templates directory", keyType)
	}
	if templatestore.TemplateExists(keyType, templatestore.TemplateTypeGeneric) {
		return fmt.Errorf("key type %s already exists as a generic template", keyType)
	}

	// Check for collision with any registered provider (built-in)
	if lsigprovider.Has(keyType) {
		return fmt.Errorf("key type %s is already registered as a built-in provider", keyType)
	}

	// Prompt for passphrase
	fmt.Print("Enter passphrase: ")
	passphraseStr, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()

	// Load keystore metadata and derive master key
	meta, err := crypto.LoadKeystoreMetadata(utilkeys.KeystorePath())
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("keystore not initialized (missing .keystore file)")
	}

	masterKey, err := meta.VerifyAndDeriveMasterKey([]byte(passphraseStr))
	if err != nil {
		return fmt.Errorf("invalid passphrase: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)

	// Save the template using the common templatestore
	outputPath, err := templatestore.SaveTemplate(data, keyType, templatestore.TemplateTypeFalcon, masterKey)
	if err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	fmt.Printf("✓ Falcon template %s added successfully\n", keyType)
	fmt.Printf("  File: %s\n", outputPath)
	fmt.Printf("  Family: %s\n", spec.Family)
	fmt.Printf("  Version: %d\n", spec.Version)
	fmt.Printf("  Display name: %s\n", spec.DisplayName)
	fmt.Printf("  TEAL suffix: %d lines\n", len(strings.Split(strings.TrimSpace(spec.TEAL), "\n")))
	fmt.Println("\nThe template will be available after unlocking apsignerd.")
	return nil
}
