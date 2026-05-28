//go:build ignore

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// migrate-falcon1024-v1-salt adds the current LogicSig salt metadata to legacy
// aplane.falcon1024.v1 key files that already contain salted bytecode but do
// not persist salt_counter in the decrypted key JSON.
//
// This is an offline, pre-release migration helper. It does not rederive
// LogicSigs or change account addresses; it extracts the existing counter from
// the stored bytecode's bytecblock salt slot and writes that metadata back into
// the encrypted key file.
//
// Usage:
//
//	go run ./scripts/migrate-falcon1024-v1-salt.go --store ~/aplanex/apsigner
//	APLANE_STORE_PASSPHRASE=... go run ./scripts/migrate-falcon1024-v1-salt.go --store ~/aplanex/apsigner --apply --passphrase-env APLANE_STORE_PASSPHRASE
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"golang.org/x/term"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const targetKeyType = "aplane.falcon1024.v1"

type options struct {
	storeDir       string
	identity       string
	apply          bool
	passphraseEnv  string
	passphraseFile string
}

type migration struct {
	opts       options
	paths      storepaths.Paths
	backupRoot string
	backedUp   map[string]bool
	masterKeys map[string][]byte
	changed    []string
	skipped    []string
}

type falconKeyFile struct {
	Category               string `json:"category"`
	KeyType                string `json:"key_type"`
	LSigBytecodeHex        string `json:"lsig_bytecode"`
	SaltCounter            *byte  `json:"salt_counter"`
	SigningMetadataVersion int    `json:"signing_metadata_version"`
	BaseKeyType            string `json:"base_key_type"`
}

func main() {
	var opts options
	defaultStore := os.Getenv("APSIGNER_DATA")
	if defaultStore == "" {
		defaultStore = "~/aplanex/apsigner"
	}
	flag.StringVar(&opts.storeDir, "store", defaultStore, "signer store directory")
	flag.StringVar(&opts.identity, "identity", "", "identity to migrate; default migrates all identities")
	flag.BoolVar(&opts.apply, "apply", false, "write changes; default is dry-run")
	flag.StringVar(&opts.passphraseEnv, "passphrase-env", "", "environment variable containing the store passphrase")
	flag.StringVar(&opts.passphraseFile, "passphrase-file", "", "file containing the store passphrase")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	storeDir, err := expandPath(opts.storeDir)
	if err != nil {
		return err
	}
	opts.storeDir = storeDir

	m := &migration{
		opts:       opts,
		paths:      storepaths.NewPaths(storeDir),
		backedUp:   map[string]bool{},
		masterKeys: map[string][]byte{},
	}
	defer m.zeroMasterKeys()

	identities, err := discoverIdentities(storeDir, opts.identity)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return fmt.Errorf("no identities found under %s", filepath.Join(storeDir, "identities"))
	}

	if opts.apply {
		guard, err := storelock.AcquireExclusive(storeDir)
		if err != nil {
			if errors.Is(err, storelock.ErrBusy) {
				return fmt.Errorf("store is locked; stop apsigner/apstore before applying migration")
			}
			return err
		}
		defer guard.Close()
		m.backupRoot = filepath.Join(storeDir, "migration-backups", "falcon1024-v1-salt-"+time.Now().UTC().Format("20060102-150405"))
	}

	passphrase, err := readPassphrase(opts)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(passphrase)

	for _, identity := range identities {
		masterKey, err := deriveMasterKey(m.paths, identity, passphrase)
		if err != nil {
			return fmt.Errorf("identity %s: %w", identity, err)
		}
		m.masterKeys[identity] = masterKey
	}

	for _, identity := range identities {
		if err := m.migrateIdentity(identity); err != nil {
			return err
		}
	}

	sort.Strings(m.changed)
	sort.Strings(m.skipped)
	if opts.apply {
		fmt.Printf("Applied Falcon-1024 v1 salt metadata migration to %s\n", storeDir)
		fmt.Printf("Backup directory: %s\n", m.backupRoot)
	} else {
		fmt.Println("Dry run only. Re-run with --apply to write changes.")
	}
	if len(m.changed) == 0 {
		fmt.Println("No changes needed.")
	} else {
		fmt.Println("Planned/applied changes:")
		for _, change := range m.changed {
			fmt.Printf("  - %s\n", change)
		}
	}
	if len(m.skipped) > 0 {
		fmt.Println("Skipped:")
		for _, skipped := range m.skipped {
			fmt.Printf("  - %s\n", skipped)
		}
	}
	return nil
}

func (m *migration) migrateIdentity(identity string) error {
	keysDir := m.paths.KeysDir(identity)
	entries, err := os.ReadDir(keysDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		path := filepath.Join(keysDir, entry.Name())
		if err := m.migrateKeyFile(identity, path); err != nil {
			return err
		}
	}
	return nil
}

func (m *migration) migrateKeyFile(identity, path string) error {
	plaintext, err := m.readEncryptedKey(identity, path)
	if err != nil {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: %v", path, err))
		return nil
	}
	defer crypto.ZeroBytes(plaintext)

	var meta falconKeyFile
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: parse key JSON: %v", path, err))
		return nil
	}
	if meta.KeyType != targetKeyType {
		return nil
	}
	if meta.Category != "" && meta.Category != keys.CategoryDSALsig {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: key_type is %s but category is %q", path, targetKeyType, meta.Category))
		return nil
	}
	if strings.TrimSpace(meta.LSigBytecodeHex) == "" {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: %s key is missing lsig_bytecode", path, targetKeyType))
		return nil
	}

	bytecode, err := hex.DecodeString(meta.LSigBytecodeHex)
	if err != nil {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: decode lsig_bytecode: %v", path, err))
		return nil
	}
	defer crypto.ZeroBytes(bytecode)

	extractedCounter, err := lsigsalt.CounterFromBytecode(bytecode, lsigsalt.BytecblockLocator)
	if err != nil {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: extract salt counter: %v", path, err))
		return nil
	}
	if meta.SaltCounter != nil && *meta.SaltCounter != extractedCounter {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: stored salt_counter %d does not match bytecode counter %d", path, *meta.SaltCounter, extractedCounter))
		return nil
	}
	address, err := logicSigAddress(bytecode)
	if err != nil {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: derive LogicSig address: %v", path, err))
		return nil
	}
	if lsigsalt.IsOnCurve(address) {
		m.skipped = append(m.skipped, fmt.Sprintf("%s: stored LogicSig address %s is on-curve", path, address.String()))
		return nil
	}

	var obj map[string]any
	if err := json.Unmarshal(plaintext, &obj); err != nil {
		return fmt.Errorf("%s: parse key object: %w", path, err)
	}
	changed := false
	if meta.Category == "" {
		obj["category"] = keys.CategoryDSALsig
		changed = true
	}
	if meta.SaltCounter == nil {
		obj["salt_counter"] = int(extractedCounter)
		changed = true
	}
	if meta.SigningMetadataVersion == 0 {
		obj["signing_metadata_version"] = keys.CurrentSigningMetadataVersion
		changed = true
	}
	if strings.TrimSpace(meta.BaseKeyType) == "" {
		obj["base_key_type"] = targetKeyType
		changed = true
	}
	if !changed {
		return nil
	}

	updated, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: marshal migrated key JSON: %w", path, err)
	}
	updated = append(updated, '\n')
	if _, err := keys.ValidateLogicSigSaltedBytecode(updated, bytecode); err != nil {
		return fmt.Errorf("%s: migrated key failed salt validation: %w", path, err)
	}

	fileAddress := strings.TrimSuffix(filepath.Base(path), ".key")
	label := fmt.Sprintf("identity %s key %s: add salt_counter=%d, signing metadata for %s", identity, fileAddress, extractedCounter, targetKeyType)
	if fileAddress != address.String() {
		label += fmt.Sprintf(" (stored bytecode address is %s)", address.String())
	}
	return m.writeKey(path, updated, label)
}

func (m *migration) readEncryptedKey(identity, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !crypto.IsEncrypted(data) {
		return nil, fmt.Errorf("key file is not encrypted")
	}
	masterKey := m.masterKeys[identity]
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("missing master key")
	}
	plaintext, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func (m *migration) writeKey(path string, plaintext []byte, label string) error {
	if !m.opts.apply {
		m.changed = append(m.changed, label)
		return nil
	}
	if err := m.backup(path); err != nil {
		return err
	}
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, m.masterKeyForPath(path))
	if err != nil {
		return fmt.Errorf("%s: encrypt migrated key: %w", path, err)
	}
	if err := fsutil.WriteFile(path, encrypted); err != nil {
		return err
	}
	m.changed = append(m.changed, label)
	return nil
}

func (m *migration) masterKeyForPath(path string) []byte {
	for identity, key := range m.masterKeys {
		keysDir := m.paths.KeysDir(identity)
		if rel, err := filepath.Rel(keysDir, path); err == nil && !strings.HasPrefix(rel, "..") {
			return key
		}
	}
	return nil
}

func (m *migration) backup(path string) error {
	if m.backedUp[path] {
		return nil
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(m.opts.storeDir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel = strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	}
	dst := filepath.Join(m.backupRoot, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o770); err != nil {
		return err
	}
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	m.backedUp[path] = true
	return nil
}

func logicSigAddress(bytecode []byte) (types.Address, error) {
	lsig := algocrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	return lsig.Address()
}

func discoverIdentities(storeDir, selected string) ([]string, error) {
	if selected != "" {
		return []string{selected}, nil
	}
	root := filepath.Join(storeDir, "identities")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var identities []string
	for _, entry := range entries {
		if entry.IsDir() {
			identities = append(identities, entry.Name())
		}
	}
	sort.Strings(identities)
	return identities, nil
}

func deriveMasterKey(paths storepaths.Paths, identity string, passphrase []byte) ([]byte, error) {
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identity))
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, fmt.Errorf("missing .keystore")
	}
	return meta.VerifyAndDeriveMasterKey(passphrase)
}

func readPassphrase(opts options) ([]byte, error) {
	switch {
	case opts.passphraseEnv != "":
		value, ok := os.LookupEnv(opts.passphraseEnv)
		if !ok {
			return nil, fmt.Errorf("passphrase env var %s is not set", opts.passphraseEnv)
		}
		return []byte(value), nil
	case opts.passphraseFile != "":
		data, err := os.ReadFile(opts.passphraseFile)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(data, "\r\n"), nil
	default:
		fmt.Fprint(os.Stderr, "Store passphrase: ")
		passphrase, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		return passphrase, nil
	}
}

func expandPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("store path is required")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return filepath.Abs(path)
}

func (m *migration) zeroMasterKeys() {
	for identity, key := range m.masterKeys {
		crypto.ZeroBytes(key)
		delete(m.masterKeys, identity)
	}
}
