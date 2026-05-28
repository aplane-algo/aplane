// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keymigration repairs known outdated key-file states outside the
// normal signer runtime.
package keymigration

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const toolName = "apkey-migrate"

// Options controls the key state repair pass.
type Options struct {
	DataDir    string
	Identity   string
	Passphrase []byte
	Apply      bool
	Now        func() time.Time
	Out        io.Writer
}

// Result summarizes a migration run.
type Result struct {
	DataDir        string
	BackupDir      string
	Repaired       int
	Current        int
	Failed         int
	RepairedFiles  []string
	CurrentFiles   []string
	FailedMessages []string
}

// SupportedConditions describes the outdated key-file states this tool can
// repair safely.
func SupportedConditions() []string {
	return []string{
		"missing or zero format_version",
		"missing category when it can be inferred from key_type and key material",
		"legacy runtime_args field when signing_args is absent or identical",
		"missing LogicSig salt_counter when the counter can be recovered from a known salt marker",
		"missing LogicSig signing_metadata_version",
		"missing DSA LogicSig base_key_type when it can be inferred from key_type",
		"missing generic LogicSig address when it matches the derived bytecode address",
	}
}

// PrintSupportedConditions writes the operator-facing list of repairable
// outdated states.
func PrintSupportedConditions(out io.Writer) {
	if out == nil {
		return
	}
	_, _ = fmt.Fprintln(out, "Supported key state repairs:")
	for _, condition := range SupportedConditions() {
		_, _ = fmt.Fprintf(out, "  - %s\n", condition)
	}
}

// Run scans key files and optionally applies known state repairs. Dry-run is
// the default when Options.Apply is false.
func Run(opts Options) (Result, error) {
	if opts.DataDir == "" {
		return Result{}, fmt.Errorf("data directory is required")
	}
	if len(opts.Passphrase) == 0 {
		return Result{}, fmt.Errorf("store passphrase is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	dataDir, err := expandPath(opts.DataDir)
	if err != nil {
		return Result{}, err
	}
	opts.DataDir = dataDir
	paths := storepaths.NewPaths(dataDir)
	result := Result{DataDir: dataDir}

	identities, err := discoverIdentities(dataDir, opts.Identity)
	if err != nil {
		return result, err
	}
	if len(identities) == 0 {
		return result, fmt.Errorf("no identities found under %s", filepath.Join(dataDir, "identities"))
	}

	var guard *storelock.Guard
	if opts.Apply {
		guard, err = storelock.AcquireExclusive(dataDir)
		if err != nil {
			if errors.Is(err, storelock.ErrBusy) {
				return result, fmt.Errorf("store is locked; stop apsigner/apstore before applying key state repairs")
			}
			return result, err
		}
		defer func() {
			_ = guard.Close()
		}()
		result.BackupDir = filepath.Join(dataDir, "migration-backups", toolName+"-"+opts.Now().UTC().Format("20060102-150405"))
	}

	for _, identity := range identities {
		masterKey, err := deriveMasterKey(paths, identity, opts.Passphrase)
		if err != nil {
			return result, fmt.Errorf("identity %s: %w", identity, err)
		}
		if err := migrateIdentity(paths, identity, masterKey, opts.Apply, result.BackupDir, &result); err != nil {
			crypto.ZeroBytes(masterKey)
			return result, err
		}
		crypto.ZeroBytes(masterKey)
	}

	sort.Strings(result.RepairedFiles)
	sort.Strings(result.CurrentFiles)
	sort.Strings(result.FailedMessages)
	printSummary(opts, result)
	return result, nil
}

func migrateIdentity(paths storepaths.Paths, identity string, masterKey []byte, apply bool, backupRoot string, result *Result) error {
	keysDir := paths.KeysDir(identity)
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
		migrateKeyFile(paths, identity, path, masterKey, apply, backupRoot, result)
	}
	return nil
}

func migrateKeyFile(paths storepaths.Paths, identity, path string, masterKey []byte, apply bool, backupRoot string, result *Result) {
	plaintext, err := keys.ReadDecryptedKeyJSONWithMasterKey(path, masterKey)
	if err != nil {
		result.Failed++
		result.FailedMessages = append(result.FailedMessages, fmt.Sprintf("%s: decrypt/read: %v", path, err))
		return
	}
	defer crypto.ZeroBytes(plaintext)

	updated, changed, err := NormalizeKeyPayloadState(plaintext)
	if err != nil {
		result.Failed++
		result.FailedMessages = append(result.FailedMessages, fmt.Sprintf("%s: %v", path, err))
		return
	}
	if !changed {
		result.Current++
		result.CurrentFiles = append(result.CurrentFiles, path)
		return
	}
	defer crypto.ZeroBytes(updated)

	if !apply {
		result.Repaired++
		result.RepairedFiles = append(result.RepairedFiles, path)
		return
	}
	if err := backupOriginal(path, backupRoot, paths.Root()); err != nil {
		result.Failed++
		result.FailedMessages = append(result.FailedMessages, fmt.Sprintf("%s: backup: %v", path, err))
		return
	}
	encrypted, err := crypto.EncryptWithMasterKey(updated, masterKey)
	if err != nil {
		result.Failed++
		result.FailedMessages = append(result.FailedMessages, fmt.Sprintf("%s: encrypt repaired payload: %v", path, err))
		return
	}
	defer crypto.ZeroBytes(encrypted)
	if err := fsutil.WriteFile(path, encrypted); err != nil {
		result.Failed++
		result.FailedMessages = append(result.FailedMessages, fmt.Sprintf("%s: write repaired payload: %v", path, err))
		return
	}
	result.Repaired++
	result.RepairedFiles = append(result.RepairedFiles, path)
}

// NormalizeKeyPayloadState repairs known outdated key-file conditions that can
// be inferred safely from the decrypted payload itself. A payload is considered
// current only after all known repair conditions have been checked and the
// result satisfies the current runtime invariants.
func NormalizeKeyPayloadState(data []byte) ([]byte, bool, error) {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, false, fmt.Errorf("parse key JSON: %w", err)
	}

	keyType, _ := stringField(obj, "key_type")
	if keyType == "" {
		return nil, false, fmt.Errorf("missing key_type; cannot repair")
	}

	changed := false
	if version, ok, err := intField(obj, "format_version"); err != nil {
		return nil, false, err
	} else if !ok || version == 0 {
		obj["format_version"] = keys.CurrentKeyFormatVersion
		changed = true
	} else if version != keys.CurrentKeyFormatVersion {
		return nil, false, fmt.Errorf("unsupported format_version %d; no state repair is available", version)
	}

	category, _ := stringField(obj, "category")
	if category == "" {
		inferred, err := inferCategory(keyType, obj)
		if err != nil {
			return nil, false, err
		}
		obj["category"] = inferred
		category = inferred
		changed = true
	}
	if legacyArgs, ok := obj["runtime_args"]; ok {
		if currentArgs, exists := obj["signing_args"]; exists && !reflect.DeepEqual(currentArgs, legacyArgs) {
			return nil, false, fmt.Errorf("both runtime_args and signing_args are present with different values; cannot repair safely")
		}
		obj["signing_args"] = legacyArgs
		delete(obj, "runtime_args")
		changed = true
	}

	bytecodeHex := firstStringField(obj, "lsig_bytecode", "bytecode_hex")
	if bytecodeHex != "" {
		bytecode, err := hex.DecodeString(bytecodeHex)
		if err != nil {
			return nil, false, fmt.Errorf("decode LogicSig bytecode: %w", err)
		}
		defer crypto.ZeroBytes(bytecode)

		if _, ok, err := intField(obj, "salt_counter"); err != nil {
			return nil, false, err
		} else if !ok {
			counter, err := inferSaltCounter(bytecode)
			if err != nil {
				return nil, false, fmt.Errorf("missing salt_counter and could not recover it: %w", err)
			}
			obj["salt_counter"] = int(counter)
			changed = true
		}
		if version, ok, err := intField(obj, "signing_metadata_version"); err != nil {
			return nil, false, err
		} else if !ok || version == 0 {
			obj["signing_metadata_version"] = keys.CurrentSigningMetadataVersion
			changed = true
		}
		if category == keys.CategoryDSALsig {
			if baseKeyType, _ := stringField(obj, "base_key_type"); baseKeyType == "" {
				obj["base_key_type"] = inferBaseKeyType(keyType)
				changed = true
			}
		}
		if category == keys.CategoryGenericLsig {
			if address, _ := logicSigAddress(bytecode); address != "" {
				if storedAddress, _ := stringField(obj, "address"); storedAddress == "" {
					obj["address"] = address
					changed = true
				} else if storedAddress != address {
					return nil, false, fmt.Errorf("generic LogicSig address mismatch: stored=%s derived=%s", storedAddress, address)
				}
			}
		}
	}

	normalized, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("marshal repaired key JSON: %w", err)
	}
	if _, err := keys.ValidateCurrentKeyPayload(normalized); err != nil {
		crypto.ZeroBytes(normalized)
		return nil, false, err
	}
	if bytecode := keys.ExtractBytecode(normalized); len(bytecode) > 0 {
		if _, err := keys.ValidateLogicSigSaltedBytecode(normalized, bytecode); err != nil {
			crypto.ZeroBytes(normalized)
			return nil, false, err
		}
	}
	if !changed {
		crypto.ZeroBytes(normalized)
		return nil, false, nil
	}
	return normalized, changed, nil
}

func inferCategory(keyType string, obj map[string]any) (string, error) {
	privateKey, _ := stringField(obj, "private_key")
	bytecode := firstStringField(obj, "lsig_bytecode", "bytecode_hex")
	switch {
	case keyType == keys.CategoryEd25519:
		return keys.CategoryEd25519, nil
	case bytecode != "" && privateKey == "":
		return keys.CategoryGenericLsig, nil
	case bytecode != "" && privateKey != "":
		return keys.CategoryDSALsig, nil
	default:
		return "", fmt.Errorf("missing category and unable to infer it for key_type %q", keyType)
	}
}

func inferBaseKeyType(keyType string) string {
	if strings.HasPrefix(keyType, "aplane.falcon1024-") {
		return "aplane.falcon1024.v1"
	}
	return keyType
}

func inferSaltCounter(bytecode []byte) (byte, error) {
	var found []byte
	for _, locator := range []lsigsalt.Locator{lsigsalt.BytecblockPreambleLocator, lsigsalt.PushbytesMarkerLocator} {
		counter, err := lsigsalt.CounterFromBytecode(bytecode, locator)
		if err == nil {
			found = append(found, counter)
		}
	}
	if len(found) == 0 {
		return 0, fmt.Errorf("no known salt marker found")
	}
	for _, counter := range found[1:] {
		if counter != found[0] {
			return 0, fmt.Errorf("conflicting known salt markers found")
		}
	}
	return found[0], nil
}

func backupOriginal(path, backupRoot, dataRoot string) error {
	rel, err := filepath.Rel(dataRoot, path)
	if err != nil {
		return err
	}
	dest := filepath.Join(backupRoot, rel)
	if err := fsutil.MkdirAll(filepath.Dir(dest)); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(dest, data)
}

func discoverIdentities(dataDir, requested string) ([]string, error) {
	if requested != "" {
		return []string{requested}, nil
	}
	root := filepath.Join(dataDir, "identities")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func deriveMasterKey(paths storepaths.Paths, identity string, passphrase []byte) ([]byte, error) {
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identity))
	if err != nil {
		return nil, fmt.Errorf("load keystore metadata: %w", err)
	}
	if meta == nil {
		return nil, fmt.Errorf("keystore not initialized")
	}
	return meta.VerifyAndDeriveMasterKey(passphrase)
}

func printSummary(opts Options, result Result) {
	out := opts.Out
	if out == nil {
		return
	}
	if opts.Apply {
		_, _ = fmt.Fprintf(out, "Applied key state repairs to %s\n", result.DataDir)
		if result.BackupDir != "" {
			_, _ = fmt.Fprintf(out, "Backup directory: %s\n", result.BackupDir)
		}
	} else {
		_, _ = fmt.Fprintln(out, "Dry run only. Re-run with --apply to write changes.")
	}
	_, _ = fmt.Fprintf(out, "Repaired: %d\n", result.Repaired)
	_, _ = fmt.Fprintf(out, "Already current: %d\n", result.Current)
	_, _ = fmt.Fprintf(out, "Failed: %d\n", result.Failed)
	if len(result.RepairedFiles) > 0 {
		label := "Would repair:"
		if opts.Apply {
			label = "Repaired:"
		}
		_, _ = fmt.Fprintln(out, label)
		for _, path := range result.RepairedFiles {
			_, _ = fmt.Fprintf(out, "  - %s\n", path)
		}
	}
	if len(result.FailedMessages) > 0 {
		_, _ = fmt.Fprintln(out, "Failures:")
		for _, msg := range result.FailedMessages {
			_, _ = fmt.Fprintf(out, "  - %s\n", msg)
		}
	}
}

func expandPath(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return filepath.Abs(path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	return "", fmt.Errorf("unsupported home-relative path %q", path)
}

func stringField(obj map[string]any, key string) (string, bool) {
	value, ok := obj[key]
	if !ok || value == nil {
		return "", false
	}
	s, ok := value.(string)
	return strings.TrimSpace(s), ok
}

func firstStringField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := stringField(obj, key); ok && value != "" {
			return value
		}
	}
	return ""
}

func intField(obj map[string]any, key string) (int, bool, error) {
	value, ok := obj[key]
	if !ok || value == nil {
		return 0, false, nil
	}
	switch v := value.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, true, fmt.Errorf("%s must be an integer", key)
		}
		return int(v), true, nil
	case int:
		return v, true, nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, true, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return int(n), true, nil
	default:
		return 0, true, fmt.Errorf("%s must be an integer", key)
	}
}

func logicSigAddress(bytecode []byte) (string, error) {
	lsig := sdkcrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	addr, err := lsig.Address()
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
