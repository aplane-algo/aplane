//go:build ignore

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// migrate-keytype-prefix upgrades pre-namespace APlane key type names in an
// offline signer store to the canonical publisher.family.vN format.
//
// Usage:
//
//	go run ./scripts/migrate-keytype-prefix.go --store ~/aplanex/apsigner
//	APLANE_STORE_PASSPHRASE=... go run ./scripts/migrate-keytype-prefix.go --store ~/aplanex/apsigner --apply --passphrase-env APLANE_STORE_PASSPHRASE
package main

import (
	"bytes"
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

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

const (
	sourceYAMLGeneric  = "yaml_generic"
	sourceYAMLComposed = "yaml_composed"
	templateGeneric    = "generic"
	templateComposed   = "composed"
)

var keyTypeMap = map[string]string{
	"falcon1024-v1":                  "aplane.falcon1024.v1",
	"falcon1024_ed25519-v1":          "aplane.falcon1024_ed25519.v1",
	"ecdsak1-v1":                     "aplane.ecdsak1.v1",
	"timed-whitelist-v1":             "aplane.timed-whitelist.v1",
	"whitelist-v1":                   "aplane.whitelist.v1",
	"htlc-v1":                        "aplane.htlc.v1",
	"falcon1024-whitelist-v1":        "aplane.falcon1024-whitelist.v1",
	"falcon1024-hashlock-v1":         "aplane.falcon1024-hashlock.v1",
	"falcon1024-timelock-v1":         "aplane.falcon1024-timelock.v1",
	"aplane-falcon1024-v1":           "aplane.falcon1024.v1",
	"aplane-ecdsak1-v1":              "aplane.ecdsak1.v1",
	"aplane-falcon1024_ed25519":      "aplane.falcon1024_ed25519.v1",
	"aplane-falcon1024_ed25519-v1":   "aplane.falcon1024_ed25519.v1",
	"aplane.falcon1024_v1":           "aplane.falcon1024.v1",
	"aplane.falcon1024_ed25519_v1":   "aplane.falcon1024_ed25519.v1",
	"aplane.ecdsak1_v1":              "aplane.ecdsak1.v1",
	"aplane.timed-whitelist_v1":      "aplane.timed-whitelist.v1",
	"aplane.whitelist_v1":            "aplane.whitelist.v1",
	"aplane.htlc_v1":                 "aplane.htlc.v1",
	"aplane.falcon1024-whitelist_v1": "aplane.falcon1024-whitelist.v1",
	"aplane.falcon1024-hashlock_v1":  "aplane.falcon1024-hashlock.v1",
	"aplane.falcon1024-timelock_v1":  "aplane.falcon1024-timelock.v1",
}

type options struct {
	storeDir       string
	identity       string
	apply          bool
	force          bool
	keepOldLibrary bool
	passphraseEnv  string
	passphraseFile string
}

type migration struct {
	opts          options
	paths         storepaths.Paths
	backupRoot    string
	backedUp      map[string]bool
	masterKeys    map[string][]byte
	fingerprints  map[string]string
	changed       []string
	libraryEvents []string
}

type stateRecord struct {
	KeyType     string `json:"key_type"`
	Source      string `json:"source"`
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ActivatedAt string `json:"activated_at"`
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
	flag.BoolVar(&opts.force, "force", false, "overwrite existing destination files")
	flag.BoolVar(&opts.keepOldLibrary, "keep-old-library", false, "leave old library YAML files in place")
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

	lsigsignerreg.RegisterSigner()

	m := &migration{
		opts:         opts,
		paths:        storepaths.NewPaths(storeDir),
		backedUp:     map[string]bool{},
		masterKeys:   map[string][]byte{},
		fingerprints: map[string]string{},
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
		m.backupRoot = filepath.Join(storeDir, "migration-backups", "keytype-prefix-"+time.Now().UTC().Format("20060102-150405"))
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
		if err := m.migrateInstalledTemplates(identity); err != nil {
			return err
		}
		if err := m.migrateStateRecords(identity); err != nil {
			return err
		}
		if err := m.migrateKeyFiles(identity); err != nil {
			return err
		}
	}
	if !opts.keepOldLibrary {
		if err := m.migrateLibraryTemplates(); err != nil {
			return err
		}
	}

	sort.Strings(m.changed)
	if opts.apply {
		fmt.Printf("Applied key type namespace migration to %s\n", storeDir)
		fmt.Printf("Backup directory: %s\n", m.backupRoot)
	} else {
		fmt.Printf("Dry run only. Re-run with --apply to write changes.\n")
	}
	if len(m.changed) == 0 {
		fmt.Println("No changes needed.")
		return nil
	}
	fmt.Println("Planned/applied changes:")
	for _, change := range m.changed {
		fmt.Printf("  - %s\n", change)
	}
	return nil
}

func (m *migration) migrateInstalledTemplates(identity string) error {
	dir := m.paths.KeyTypeRecordsDir(identity)
	records, err := readStateRecords(dir)
	if err != nil {
		return err
	}

	processed := map[string]bool{}
	for oldKeyType, rec := range records {
		newKeyType := mappedKeyType(oldKeyType)
		if newKeyType == oldKeyType {
			continue
		}
		templateType := templateTypeForSource(rec.Source)
		if templateType == "" {
			continue
		}
		oldPath := filepath.Join(dir, oldKeyType+".template")
		if _, err := os.Stat(oldPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		fp, err := m.migrateTemplateFile(identity, oldPath, oldKeyType, newKeyType, templateType)
		if err != nil {
			return err
		}
		if fp != "" {
			m.fingerprints[newKeyType] = fp
		}
		processed[oldPath] = true
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*.template"))
	if err != nil {
		return err
	}
	for _, oldPath := range matches {
		if processed[oldPath] {
			continue
		}
		oldKeyType := strings.TrimSuffix(filepath.Base(oldPath), ".template")
		newKeyType := mappedKeyType(oldKeyType)
		if newKeyType == oldKeyType {
			continue
		}
		templateType, err := m.inferTemplateType(identity, oldPath)
		if err != nil {
			return err
		}
		fp, err := m.migrateTemplateFile(identity, oldPath, oldKeyType, newKeyType, templateType)
		if err != nil {
			return err
		}
		if fp != "" {
			m.fingerprints[newKeyType] = fp
		}
	}
	return nil
}

func (m *migration) migrateTemplateFile(identity, oldPath, oldKeyType, newKeyType, templateType string) (string, error) {
	plaintext, encrypted, err := m.readMaybeEncrypted(identity, oldPath)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(plaintext)

	updated, changed, err := migrateTemplateYAML(plaintext)
	if err != nil {
		return "", fmt.Errorf("%s: %w", oldPath, err)
	}
	if !changed && oldKeyType == newKeyType {
		return "", nil
	}
	fingerprint, err := semanticFingerprint(templateType, updated)
	if err != nil {
		return "", fmt.Errorf("%s: %w", oldPath, err)
	}

	data := updated
	if encrypted {
		data, err = crypto.EncryptWithMasterKey(updated, m.masterKeys[identity])
		if err != nil {
			return "", fmt.Errorf("%s: encrypt migrated template: %w", oldPath, err)
		}
	}

	newPath := filepath.Join(filepath.Dir(oldPath), newKeyType+".template")
	if err := m.replacePath(oldPath, newPath, data, fmt.Sprintf("template %s -> %s", oldKeyType, newKeyType)); err != nil {
		return "", err
	}
	return fingerprint, nil
}

func (m *migration) migrateStateRecords(identity string) error {
	dir := m.paths.KeyTypeRecordsDir(identity)
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	for _, oldPath := range matches {
		data, err := os.ReadFile(oldPath)
		if err != nil {
			return err
		}
		var rec stateRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("%s: parse key type state: %w", oldPath, err)
		}
		oldKeyType := rec.KeyType
		if oldKeyType == "" {
			oldKeyType = strings.TrimSuffix(filepath.Base(oldPath), ".json")
		}
		newKeyType := mappedKeyType(oldKeyType)
		if newKeyType == oldKeyType {
			continue
		}
		rec.KeyType = newKeyType
		if fp := m.fingerprints[newKeyType]; fp != "" {
			rec.Fingerprint = fp
		}
		updated, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		updated = append(updated, '\n')
		newPath := filepath.Join(filepath.Dir(oldPath), newKeyType+".json")
		if err := m.replacePath(oldPath, newPath, updated, fmt.Sprintf("state %s -> %s", oldKeyType, newKeyType)); err != nil {
			return err
		}
	}
	return nil
}

func (m *migration) migrateKeyFiles(identity string) error {
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
		plaintext, encrypted, err := m.readMaybeEncrypted(identity, path)
		if err != nil {
			return err
		}
		updated, changed, err := m.migrateKeyJSON(plaintext)
		crypto.ZeroBytes(plaintext)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !changed {
			continue
		}
		data := updated
		if encrypted {
			data, err = crypto.EncryptWithMasterKey(updated, m.masterKeys[identity])
			if err != nil {
				return fmt.Errorf("%s: encrypt migrated key: %w", path, err)
			}
		}
		if err := m.writeSamePath(path, data, "key file "+entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (m *migration) migrateKeyJSON(data []byte) ([]byte, bool, error) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, false, fmt.Errorf("parse key JSON: %w", err)
	}
	changed := false
	if updateMappedString(obj, "key_type") {
		changed = true
	}
	if updateMappedString(obj, "base_key_type") {
		changed = true
	}
	if keyType, _ := obj["key_type"].(string); keyType != "" {
		if fp := m.fingerprints[keyType]; fp != "" {
			if existing, _ := obj["template_fingerprint"].(string); existing != "" && existing != fp {
				obj["template_fingerprint"] = fp
				changed = true
			}
		}
	}
	if !changed {
		return nil, false, nil
	}
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(out, '\n'), true, nil
}

func (m *migration) migrateLibraryTemplates() error {
	dir := m.paths.TemplateLibraryDir()
	for oldKeyType, newKeyType := range keyTypeMap {
		oldPath := filepath.Join(dir, oldKeyType+".yaml")
		if _, err := os.Stat(oldPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		newPath := filepath.Join(dir, newKeyType+".yaml")
		if _, err := os.Stat(newPath); err == nil {
			if err := m.removePath(oldPath, fmt.Sprintf("remove old library template %s", filepath.Base(oldPath))); err != nil {
				return err
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		data, err := os.ReadFile(oldPath)
		if err != nil {
			return err
		}
		updated, _, err := migrateTemplateYAML(data)
		if err != nil {
			return fmt.Errorf("%s: %w", oldPath, err)
		}
		if err := m.replacePath(oldPath, newPath, updated, fmt.Sprintf("library template %s -> %s", filepath.Base(oldPath), filepath.Base(newPath))); err != nil {
			return err
		}
	}
	return nil
}

func migrateTemplateYAML(data []byte) ([]byte, bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("parse YAML: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("template YAML root must be a mapping")
	}
	root := doc.Content[0]
	changed := false
	if setYAMLScalar(root, "publisher", "aplane", "template_mode", false) {
		changed = true
	}
	if updateYAMLKeyType(root, "base_key_type") {
		changed = true
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false, err
	}
	if err := enc.Close(); err != nil {
		return nil, false, err
	}
	return buf.Bytes(), changed, nil
}

func setYAMLScalar(root *yaml.Node, key, value, after string, overwrite bool) bool {
	if idx := yamlKeyIndex(root, key); idx >= 0 {
		val := root.Content[idx+1]
		if val.Value == value || (!overwrite && strings.TrimSpace(val.Value) != "") {
			return false
		}
		val.Kind = yaml.ScalarNode
		val.Tag = "!!str"
		val.Value = value
		return true
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	insert := len(root.Content)
	if afterIdx := yamlKeyIndex(root, after); afterIdx >= 0 {
		insert = afterIdx + 2
	}
	root.Content = append(root.Content, nil, nil)
	copy(root.Content[insert+2:], root.Content[insert:])
	root.Content[insert] = keyNode
	root.Content[insert+1] = valNode
	return true
}

func updateYAMLKeyType(root *yaml.Node, key string) bool {
	idx := yamlKeyIndex(root, key)
	if idx < 0 {
		return false
	}
	val := root.Content[idx+1]
	next := mappedKeyType(strings.TrimSpace(val.Value))
	if next == val.Value {
		return false
	}
	val.Value = next
	val.Tag = "!!str"
	return true
}

func yamlKeyIndex(root *yaml.Node, key string) int {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func semanticFingerprint(templateType string, data []byte) (string, error) {
	switch templateType {
	case templateGeneric:
		return generictemplate.SemanticFingerprint(data)
	case templateComposed:
		return composeddsa.SemanticFingerprint(data)
	default:
		return "", fmt.Errorf("unsupported template type %q", templateType)
	}
}

func (m *migration) inferTemplateType(identity, path string) (string, error) {
	data, _, err := m.readMaybeEncrypted(identity, path)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(data)
	var doc struct {
		TemplateType string `yaml:"template_type"`
		BaseKeyType  string `yaml:"base_key_type"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("%s: parse YAML: %w", path, err)
	}
	switch strings.TrimSpace(doc.TemplateType) {
	case "", templateGeneric:
		if strings.TrimSpace(doc.BaseKeyType) != "" {
			return templateComposed, nil
		}
		return templateGeneric, nil
	case templateComposed:
		return templateComposed, nil
	default:
		return "", fmt.Errorf("%s: unsupported template_type %q", path, doc.TemplateType)
	}
}

func (m *migration) readMaybeEncrypted(identity, path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if !crypto.IsEncrypted(data) {
		return data, false, nil
	}
	masterKey := m.masterKeys[identity]
	if len(masterKey) == 0 {
		return nil, false, fmt.Errorf("%s: encrypted file requires master key", path)
	}
	plaintext, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, false, fmt.Errorf("%s: decrypt: %w", path, err)
	}
	return plaintext, true, nil
}

func (m *migration) replacePath(oldPath, newPath string, data []byte, label string) error {
	if oldPath != newPath {
		if _, err := os.Stat(newPath); err == nil && !m.opts.force {
			return fmt.Errorf("destination exists for %s: %s; use --force to overwrite", label, newPath)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if !m.opts.apply {
		m.changed = append(m.changed, label)
		return nil
	}
	if oldPath != newPath {
		if err := m.backup(oldPath); err != nil {
			return err
		}
		if _, err := os.Stat(newPath); err == nil {
			if err := m.backup(newPath); err != nil {
				return err
			}
		}
		if err := fsutil.WriteFile(newPath, data); err != nil {
			return err
		}
		if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		if err := m.backup(oldPath); err != nil {
			return err
		}
		if err := fsutil.WriteFile(oldPath, data); err != nil {
			return err
		}
	}
	m.changed = append(m.changed, label)
	return nil
}

func (m *migration) writeSamePath(path string, data []byte, label string) error {
	return m.replacePath(path, path, data, label)
}

func (m *migration) removePath(path, label string) error {
	if !m.opts.apply {
		m.changed = append(m.changed, label)
		return nil
	}
	if err := m.backup(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	m.changed = append(m.changed, label)
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

func readStateRecords(dir string) (map[string]stateRecord, error) {
	out := map[string]stateRecord{}
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var rec stateRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("%s: parse key type state: %w", path, err)
		}
		keyType := rec.KeyType
		if keyType == "" {
			keyType = strings.TrimSuffix(filepath.Base(path), ".json")
		}
		out[keyType] = rec
	}
	return out, nil
}

func templateTypeForSource(source string) string {
	switch source {
	case sourceYAMLGeneric:
		return templateGeneric
	case sourceYAMLComposed:
		return templateComposed
	default:
		return ""
	}
}

func updateMappedString(obj map[string]any, key string) bool {
	current, ok := obj[key].(string)
	if !ok || current == "" {
		return false
	}
	next := mappedKeyType(current)
	if next == current {
		return false
	}
	obj[key] = next
	return true
}

func mappedKeyType(keyType string) string {
	normalized := strings.ToLower(strings.TrimSpace(keyType))
	if next, ok := keyTypeMap[normalized]; ok {
		return next
	}
	return keyType
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
