// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package recovered owns destination-encrypted backup recovery batches.
//
// Recovered entries are deliberately not managed .key or .sen files. The
// signer runtime ignores this package's on-disk directory until a later,
// explicit activation operation applies an entry to the active store.
package recovered

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	BatchSchema = "aplane.recovered-batch.v1"
	EntrySchema = "aplane.recovered-entry.v1"

	restoreIDBytes = 16
)

var (
	restoreIDShape = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sha256Shape    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type SourcePolicyStatus string

const (
	SourcePolicyUnverified SourcePolicyStatus = "unverified"
	SourcePolicyMissing    SourcePolicyStatus = "missing"
	SourcePolicyInvalid    SourcePolicyStatus = "invalid"
)

type CreateRequest struct {
	ArchiveName        string
	ArchiveSHA256      string
	SourceNodeRole     string
	SourcePolicyStatus SourcePolicyStatus
	SourcePolicySHA256 string
	SourcePolicyYAML   []byte
	CreatedAt          time.Time
	Entries            []Entry
}

type Batch struct {
	Schema             string             `json:"schema"`
	RestoreID          string             `json:"restore_id"`
	CreatedAt          time.Time          `json:"created_at"`
	ArchiveName        string             `json:"archive_name"`
	ArchiveSHA256      string             `json:"archive_sha256"`
	SourceNodeRole     string             `json:"source_node_role"`
	SourcePolicyStatus SourcePolicyStatus `json:"source_policy_status"`
	SourcePolicySHA256 string             `json:"source_policy_sha256,omitempty"`
	SourcePolicyYAML   []byte             `json:"source_policy_yaml,omitempty"`
	Entries            []BatchEntry       `json:"entries"`
}

type BatchEntry struct {
	Selector  string `json:"selector"`
	Category  string `json:"category"`
	KeyType   string `json:"key_type"`
	EntryFile string `json:"entry_file"`
}

type Entry struct {
	Schema       string `json:"schema"`
	Selector     string `json:"selector"`
	Category     string `json:"category"`
	KeyType      string `json:"key_type"`
	KeyJSON      []byte `json:"key_json"`
	TemplateYAML []byte `json:"template_yaml,omitempty"`
	TemplateType string `json:"template_type,omitempty"`
}

func NewRestoreID() (string, error) {
	var raw [restoreIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate restore ID: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func ValidateRestoreID(restoreID string) error {
	if !restoreIDShape.MatchString(restoreID) {
		return fmt.Errorf("invalid restore ID %q", restoreID)
	}
	return nil
}

func EntryFileName(selector string) string {
	sum := sha256.Sum256([]byte(selector))
	return hex.EncodeToString(sum[:]) + ".recovered"
}

func (e *Entry) ZeroSecrets() {
	if e == nil {
		return
	}
	crypto.ZeroBytes(e.KeyJSON)
	crypto.ZeroBytes(e.TemplateYAML)
}

func Create(paths storepaths.Paths, identityID string, req CreateRequest, masterKey []byte) (*Batch, error) {
	if len(req.Entries) == 0 {
		return nil, fmt.Errorf("recovered batch requires at least one entry")
	}
	restoreID, err := NewRestoreID()
	if err != nil {
		return nil, err
	}
	createdAt := req.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	entries := slices.Clone(req.Entries)
	slices.SortFunc(entries, func(a, b Entry) int {
		return strings.Compare(a.Selector, b.Selector)
	})
	batchEntries := make([]BatchEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		entry := &entries[i]
		if entry.Schema == "" {
			entry.Schema = EntrySchema
		}
		if err := validateEntry(entry); err != nil {
			return nil, fmt.Errorf("validate recovered entry %q: %w", entry.Selector, err)
		}
		if _, ok := seen[entry.Selector]; ok {
			return nil, fmt.Errorf("duplicate recovered selector %q", entry.Selector)
		}
		seen[entry.Selector] = struct{}{}
		batchEntries = append(batchEntries, BatchEntry{
			Selector:  entry.Selector,
			Category:  entry.Category,
			KeyType:   entry.KeyType,
			EntryFile: EntryFileName(entry.Selector),
		})
	}

	batch := &Batch{
		Schema:             BatchSchema,
		RestoreID:          restoreID,
		CreatedAt:          createdAt,
		ArchiveName:        req.ArchiveName,
		ArchiveSHA256:      req.ArchiveSHA256,
		SourceNodeRole:     req.SourceNodeRole,
		SourcePolicyStatus: req.SourcePolicyStatus,
		SourcePolicySHA256: req.SourcePolicySHA256,
		SourcePolicyYAML:   slices.Clone(req.SourcePolicyYAML),
		Entries:            batchEntries,
	}
	if err := validateBatch(batch); err != nil {
		return nil, err
	}

	root := paths.RecoveredRootDir(identityID)
	if err := fsutil.MkdirAll(root); err != nil {
		return nil, fmt.Errorf("create recovered root: %w", err)
	}
	stageDir, err := os.MkdirTemp(root, ".recovering-*")
	if err != nil {
		return nil, fmt.Errorf("create recovered batch staging directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := os.Chmod(stageDir, fsutil.StoreDirPerm); err != nil {
		return nil, fmt.Errorf("set recovered batch staging permissions: %w", err)
	}
	stageEntriesDir := filepath.Join(stageDir, "entries")
	if err := fsutil.MkdirAll(stageEntriesDir); err != nil {
		return nil, fmt.Errorf("create recovered entries directory: %w", err)
	}

	for i := range entries {
		plaintext, err := json.Marshal(&entries[i])
		if err != nil {
			return nil, fmt.Errorf("marshal recovered entry %q: %w", entries[i].Selector, err)
		}
		encrypted, encryptErr := crypto.EncryptWithMasterKey(plaintext, masterKey)
		crypto.ZeroBytes(plaintext)
		if encryptErr != nil {
			return nil, fmt.Errorf("encrypt recovered entry %q: %w", entries[i].Selector, encryptErr)
		}
		entryPath := filepath.Join(stageEntriesDir, EntryFileName(entries[i].Selector))
		if err := fsutil.WriteFile(entryPath, encrypted); err != nil {
			return nil, fmt.Errorf("write recovered entry %q: %w", entries[i].Selector, err)
		}
	}

	plaintext, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("marshal recovered batch: %w", err)
	}
	encrypted, encryptErr := crypto.EncryptWithMasterKey(plaintext, masterKey)
	crypto.ZeroBytes(plaintext)
	if encryptErr != nil {
		return nil, fmt.Errorf("encrypt recovered batch: %w", encryptErr)
	}
	if err := fsutil.WriteFile(filepath.Join(stageDir, "batch.enc"), encrypted); err != nil {
		return nil, fmt.Errorf("write recovered batch metadata: %w", err)
	}

	finalDir := paths.RecoveredBatchDir(identityID, restoreID)
	if _, err := os.Lstat(finalDir); err == nil {
		return nil, fmt.Errorf("recovered batch already exists: %s", restoreID)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect recovered batch destination: %w", err)
	}
	if err := os.Rename(stageDir, finalDir); err != nil {
		return nil, fmt.Errorf("publish recovered batch: %w", err)
	}
	cleanup = false
	return batch, nil
}

func LoadBatch(paths storepaths.Paths, identityID, restoreID string, masterKey []byte) (*Batch, error) {
	if err := ValidateRestoreID(restoreID); err != nil {
		return nil, err
	}
	data, err := readRegularFile(paths.RecoveredBatchMetadataPath(identityID, restoreID))
	if err != nil {
		return nil, fmt.Errorf("read recovered batch: %w", err)
	}
	plaintext, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt recovered batch: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)
	var batch Batch
	if err := json.Unmarshal(plaintext, &batch); err != nil {
		return nil, fmt.Errorf("parse recovered batch: %w", err)
	}
	if err := validateBatch(&batch); err != nil {
		return nil, err
	}
	if batch.RestoreID != restoreID {
		return nil, fmt.Errorf("recovered batch restore ID mismatch: file=%s payload=%s", restoreID, batch.RestoreID)
	}
	return &batch, nil
}

func LoadEntry(paths storepaths.Paths, identityID, restoreID string, meta BatchEntry, masterKey []byte) (*Entry, error) {
	if err := ValidateRestoreID(restoreID); err != nil {
		return nil, err
	}
	if err := validateBatchEntry(meta); err != nil {
		return nil, err
	}
	path := filepath.Join(paths.RecoveredBatchEntriesDir(identityID, restoreID), meta.EntryFile)
	data, err := readRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("read recovered entry %q: %w", meta.Selector, err)
	}
	plaintext, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt recovered entry %q: %w", meta.Selector, err)
	}
	defer crypto.ZeroBytes(plaintext)
	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		entry.ZeroSecrets()
		return nil, fmt.Errorf("parse recovered entry %q: %w", meta.Selector, err)
	}
	if err := validateEntry(&entry); err != nil {
		entry.ZeroSecrets()
		return nil, fmt.Errorf("validate recovered entry %q: %w", meta.Selector, err)
	}
	if entry.Selector != meta.Selector || entry.Category != meta.Category || entry.KeyType != meta.KeyType {
		entry.ZeroSecrets()
		return nil, fmt.Errorf("recovered entry metadata mismatch for %q", meta.Selector)
	}
	return &entry, nil
}

func validateBatch(batch *Batch) error {
	if batch == nil {
		return fmt.Errorf("recovered batch is nil")
	}
	if batch.Schema != BatchSchema {
		return fmt.Errorf("unsupported recovered batch schema %q", batch.Schema)
	}
	if err := ValidateRestoreID(batch.RestoreID); err != nil {
		return err
	}
	if batch.CreatedAt.IsZero() {
		return fmt.Errorf("recovered batch created_at is required")
	}
	if batch.ArchiveName == "" || filepath.Base(batch.ArchiveName) != batch.ArchiveName {
		return fmt.Errorf("recovered batch archive_name must be a base filename")
	}
	if !sha256Shape.MatchString(batch.ArchiveSHA256) {
		return fmt.Errorf("invalid recovered batch archive_sha256")
	}
	switch batch.SourceNodeRole {
	case string(noderole.RoleSigner), string(noderole.RoleSentry), "unknown":
	default:
		return fmt.Errorf("invalid recovered batch source_node_role %q", batch.SourceNodeRole)
	}
	switch batch.SourcePolicyStatus {
	case SourcePolicyMissing:
		if batch.SourcePolicySHA256 != "" || len(batch.SourcePolicyYAML) != 0 {
			return fmt.Errorf("missing source policy must not include policy data")
		}
	case SourcePolicyUnverified, SourcePolicyInvalid:
		if len(batch.SourcePolicyYAML) == 0 {
			return fmt.Errorf("%s source policy requires policy YAML", batch.SourcePolicyStatus)
		}
		if !sha256Shape.MatchString(batch.SourcePolicySHA256) {
			return fmt.Errorf("invalid recovered batch source_policy_sha256")
		}
		sum := sha256.Sum256(batch.SourcePolicyYAML)
		if hex.EncodeToString(sum[:]) != batch.SourcePolicySHA256 {
			return fmt.Errorf("recovered batch source policy digest mismatch")
		}
	default:
		return fmt.Errorf("invalid recovered batch source_policy_status %q", batch.SourcePolicyStatus)
	}
	if len(batch.Entries) == 0 {
		return fmt.Errorf("recovered batch requires at least one entry")
	}
	seen := make(map[string]struct{}, len(batch.Entries))
	for _, entry := range batch.Entries {
		if err := validateBatchEntry(entry); err != nil {
			return err
		}
		if _, ok := seen[entry.Selector]; ok {
			return fmt.Errorf("duplicate recovered batch selector %q", entry.Selector)
		}
		seen[entry.Selector] = struct{}{}
	}
	if !slices.IsSortedFunc(batch.Entries, func(a, b BatchEntry) int {
		return strings.Compare(a.Selector, b.Selector)
	}) {
		return fmt.Errorf("recovered batch entries are not sorted")
	}
	return nil
}

func validateBatchEntry(entry BatchEntry) error {
	if entry.Selector == "" || entry.Category == "" || entry.KeyType == "" {
		return fmt.Errorf("recovered batch entry metadata is incomplete")
	}
	if _, err := keys.CanonicalManagedCredentialFilename(entry.Selector, entry.Category); err != nil {
		return fmt.Errorf("invalid recovered batch entry selector/category: %w", err)
	}
	if entry.EntryFile != EntryFileName(entry.Selector) || filepath.Base(entry.EntryFile) != entry.EntryFile {
		return fmt.Errorf("invalid recovered entry filename for %q", entry.Selector)
	}
	return nil
}

func validateEntry(entry *Entry) error {
	if entry == nil {
		return fmt.Errorf("recovered entry is nil")
	}
	if entry.Schema != EntrySchema {
		return fmt.Errorf("unsupported recovered entry schema %q", entry.Schema)
	}
	if len(entry.KeyJSON) == 0 {
		return fmt.Errorf("recovered entry key_json is required")
	}
	if len(entry.TemplateYAML) == 0 && entry.TemplateType != "" {
		return fmt.Errorf("recovered entry has template_type without template_yaml")
	}
	if len(entry.TemplateYAML) > 0 && entry.TemplateType == "" {
		return fmt.Errorf("recovered entry has template_yaml without template_type")
	}
	payload, err := keys.ParsePayload(entry.KeyJSON)
	if err != nil {
		return fmt.Errorf("parse recovered key payload: %w", err)
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return err
	}
	if selector != entry.Selector {
		return fmt.Errorf("recovered entry selector mismatch: metadata=%s payload=%s", entry.Selector, selector)
	}
	if payload.Category != entry.Category {
		return fmt.Errorf("recovered entry category mismatch: metadata=%s payload=%s", entry.Category, payload.Category)
	}
	if payload.KeyType != entry.KeyType {
		return fmt.Errorf("recovered entry key type mismatch: metadata=%s payload=%s", entry.KeyType, payload.KeyType)
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("path is not a regular file: %s", path)
	}
	return os.ReadFile(path)
}
