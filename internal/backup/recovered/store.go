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

	"github.com/aplane-algo/aplane/internal/backup/sourcecontext"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

const (
	// BatchSchema identifies the decrypted recovered-batch metadata schema.
	BatchSchema = "aplane.recovered-batch.v1"
	// EntrySchema identifies the decrypted recovered-entry schema.
	EntrySchema = "aplane.recovered-entry.v1"
	// StagingDirPrefix identifies unpublished Create work directories. Listing
	// and rotation code must ignore these names.
	StagingDirPrefix = ".recovering-"

	restoreIDBytes        = 16
	maxArchiveNameBytes   = 255
	batchMetadataFileName = "batch.enc"
	entriesDirectoryName  = "entries"
)

var sha256Shape = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SourcePolicyStatus describes how much trust the destination can place in
// policy bytes copied from a source archive.
type SourcePolicyStatus string

const (
	// SourcePolicyUnverified means policy bytes were present but the
	// destination cannot authenticate their source-keyed HMAC.
	SourcePolicyUnverified SourcePolicyStatus = "unverified"
	// SourcePolicyMissing means the archive contained no source policy.
	SourcePolicyMissing SourcePolicyStatus = "missing"
	// SourcePolicyInvalid means policy bytes were present but could not be
	// parsed or used for advisory comparison.
	SourcePolicyInvalid SourcePolicyStatus = "invalid"
)

// SourceNodeRoleUnknown records that an archive predates trustworthy source
// node-role metadata.
const SourceNodeRoleUnknown = "unknown"

// CreateRequest contains validated recovery material to persist as one batch.
//
// Create borrows Entries, KeyJSON, TemplateYAML, SourcePolicyYAML, and source
// setting slices and pointers for the duration of the call. The caller retains
// ownership and must clear its own secret buffers.
type CreateRequest struct {
	ArchiveName   string
	ArchiveSHA256 string
	// SourceArchiveCreatedAtUnix is when the source packaged the archive,
	// taken from its sealed manifest. Review shows it so an operator can
	// notice an archive older than expected: the manifest binds members to
	// each other, not to a point in time, so substituting an older archive
	// sealed under the same passphrase is otherwise indistinguishable.
	SourceArchiveCreatedAtUnix int64
	SourceNodeRole             string
	SourcePolicyStatus         SourcePolicyStatus
	SourcePolicySHA256         string
	SourcePolicyYAML           []byte
	SourceUserAutoApprove      *bool
	SourceGenesisHashMappings  []sourcecontext.GenesisHashMapping
	CreatedAt                  time.Time
	Entries                    []Entry
}

// Batch is the destination-encrypted manifest for one recovered batch.
//
// A published batch is immutable. Callers may load it for validation but must
// never persist a re-marshaled loaded Batch because older readers intentionally
// ignore additive JSON fields. Rotation re-encrypts the exact plaintext bytes;
// activation and purge delete a batch but never rewrite it.
type Batch struct {
	Schema                     string                             `json:"schema"`
	RestoreID                  string                             `json:"restore_id"`
	CreatedAt                  time.Time                          `json:"created_at"`
	ArchiveName                string                             `json:"archive_name"`
	ArchiveSHA256              string                             `json:"archive_sha256"`
	SourceArchiveCreatedAtUnix int64                              `json:"source_archive_created_at,omitempty"`
	SourceNodeRole             string                             `json:"source_node_role"`
	SourcePolicyStatus         SourcePolicyStatus                 `json:"source_policy_status"`
	SourcePolicySHA256         string                             `json:"source_policy_sha256,omitempty"`
	SourcePolicyYAML           []byte                             `json:"source_policy_yaml,omitempty"`
	SourceUserAutoApprove      *bool                              `json:"source_user_auto_approve,omitempty"`
	SourceGenesisHashMappings  []sourcecontext.GenesisHashMapping `json:"source_genesis_hash_mappings,omitempty"`
	Entries                    []BatchEntry                       `json:"entries"`
}

// BatchEntry commits batch metadata to one exact recovered-entry plaintext.
type BatchEntry struct {
	Selector    string `json:"selector"`
	Category    string `json:"category"`
	KeyType     string `json:"key_type"`
	EntryFile   string `json:"entry_file"`
	EntrySHA256 string `json:"entry_sha256"`
}

// Entry contains one destination-encrypted recovered credential and its
// optional bundled template. Call ZeroSecrets when an opened Entry is no
// longer needed.
type Entry struct {
	Schema       string `json:"schema"`
	RestoreID    string `json:"restore_id"`
	Selector     string `json:"selector"`
	Category     string `json:"category"`
	KeyType      string `json:"key_type"`
	KeyJSON      []byte `json:"key_json"`
	TemplateYAML []byte `json:"template_yaml,omitempty"`
	TemplateType string `json:"template_type,omitempty"`
}

// NewRestoreID returns a random canonical 128-bit recovered-batch identifier.
func NewRestoreID() (string, error) {
	var raw [restoreIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate restore ID: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidateRestoreID checks the canonical recovered-batch identifier shape.
func ValidateRestoreID(restoreID string) error {
	return storepaths.ValidateRestoreIDComponent(restoreID)
}

// EntryFileName returns the non-authoritative filename for selector.
func EntryFileName(selector string) string {
	sum := sha256.Sum256([]byte(selector))
	return hex.EncodeToString(sum[:]) + ".recovered"
}

// ZeroSecrets clears credential and template plaintext owned by e.
func (e *Entry) ZeroSecrets() {
	if e == nil {
		return
	}
	crypto.ZeroBytes(e.KeyJSON)
	crypto.ZeroBytes(e.TemplateYAML)
}

// Create validates, destination-encrypts, and atomically publishes one
// recovered batch without mutating active key or key-type storage.
//
// req and masterKey are borrowed. Create does not clear caller-owned buffers
// and stores independently owned copies of all optional source context.
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
	entryPlaintexts := make([][]byte, len(entries))
	defer func() {
		for _, plaintext := range entryPlaintexts {
			crypto.ZeroBytes(plaintext)
		}
	}()
	batchEntries := make([]BatchEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		entry := &entries[i]
		if entry.Schema == "" {
			entry.Schema = EntrySchema
		}
		if entry.RestoreID == "" {
			entry.RestoreID = restoreID
		}
		if err := validateEntry(entry, restoreID); err != nil {
			return nil, fmt.Errorf("validate recovered entry %q: %w", entry.Selector, err)
		}
		if _, ok := seen[entry.Selector]; ok {
			return nil, fmt.Errorf("duplicate recovered selector %q", entry.Selector)
		}
		seen[entry.Selector] = struct{}{}
		plaintext, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("marshal recovered entry %q: %w", entry.Selector, err)
		}
		entryPlaintexts[i] = plaintext
		sum := sha256.Sum256(plaintext)
		batchEntries = append(batchEntries, BatchEntry{
			Selector:    entry.Selector,
			Category:    entry.Category,
			KeyType:     entry.KeyType,
			EntryFile:   EntryFileName(entry.Selector),
			EntrySHA256: hex.EncodeToString(sum[:]),
		})
	}

	batch := &Batch{
		Schema:                     BatchSchema,
		RestoreID:                  restoreID,
		CreatedAt:                  createdAt,
		ArchiveName:                req.ArchiveName,
		ArchiveSHA256:              req.ArchiveSHA256,
		SourceArchiveCreatedAtUnix: req.SourceArchiveCreatedAtUnix,
		SourceNodeRole:             req.SourceNodeRole,
		SourcePolicyStatus:         req.SourcePolicyStatus,
		SourcePolicySHA256:         req.SourcePolicySHA256,
		SourcePolicyYAML:           slices.Clone(req.SourcePolicyYAML),
		Entries:                    batchEntries,
	}
	sourceProjection := sourcecontext.CloneProjection(sourcecontext.Projection{
		UserAutoApprove:     req.SourceUserAutoApprove,
		GenesisHashMappings: req.SourceGenesisHashMappings,
	})
	batch.SourceUserAutoApprove = sourceProjection.UserAutoApprove
	batch.SourceGenesisHashMappings = sourceProjection.GenesisHashMappings
	if err := validateBatch(batch); err != nil {
		return nil, err
	}

	root := paths.RecoveredRootDir(identityID)
	if err := fsutil.MkdirAll(root); err != nil {
		return nil, fmt.Errorf("create recovered root: %w", err)
	}
	stageDir, err := os.MkdirTemp(root, StagingDirPrefix+"*")
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
	stageEntriesDir := filepath.Join(stageDir, entriesDirectoryName)
	if err := fsutil.MkdirAll(stageEntriesDir); err != nil {
		return nil, fmt.Errorf("create recovered entries directory: %w", err)
	}

	for i := range entries {
		plaintext := entryPlaintexts[i]
		encrypted, encryptErr := crypto.EncryptWithMasterKey(plaintext, masterKey)
		crypto.ZeroBytes(plaintext)
		entryPlaintexts[i] = nil
		if encryptErr != nil {
			return nil, fmt.Errorf("encrypt recovered entry %q: %w", entries[i].Selector, encryptErr)
		}
		entryPath := filepath.Join(stageEntriesDir, EntryFileName(entries[i].Selector))
		if err := fsutil.WriteFile(entryPath, encrypted); err != nil {
			return nil, fmt.Errorf("write recovered entry %q: %w", entries[i].Selector, err)
		}
		if err := syncRegularFile(entryPath); err != nil {
			return nil, fmt.Errorf("sync recovered entry %q: %w", entries[i].Selector, err)
		}
	}
	if err := syncDirectory(stageEntriesDir); err != nil {
		return nil, fmt.Errorf("sync recovered entries directory: %w", err)
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
	if err := fsutil.WriteFile(filepath.Join(stageDir, batchMetadataFileName), encrypted); err != nil {
		return nil, fmt.Errorf("write recovered batch metadata: %w", err)
	}
	if err := syncRegularFile(filepath.Join(stageDir, batchMetadataFileName)); err != nil {
		return nil, fmt.Errorf("sync recovered batch metadata: %w", err)
	}
	if err := syncDirectory(stageDir); err != nil {
		return nil, fmt.Errorf("sync recovered batch staging directory: %w", err)
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
	if err := syncDirectory(root); err != nil {
		_ = os.RemoveAll(finalDir)
		_ = syncDirectory(root)
		return nil, fmt.Errorf("sync recovered batch root: %w", err)
	}
	return batch, nil
}

// LoadBatch decrypts and validates one recovered-batch manifest.
func LoadBatch(paths storepaths.Paths, identityID, restoreID string, masterKey []byte) (*Batch, error) {
	if err := ValidateRestoreID(restoreID); err != nil {
		return nil, err
	}
	return loadBatchAt(paths.RecoveredBatchMetadataPath(identityID, restoreID), restoreID, masterKey)
}

func loadBatchAt(path, restoreID string, masterKey []byte) (*Batch, error) {
	data, err := readRegularFile(path)
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

// LoadEntry decrypts and validates an entry committed by meta.
//
// The returned Entry owns plaintext key and template buffers. The caller must
// call Entry.ZeroSecrets when finished.
func LoadEntry(paths storepaths.Paths, identityID, restoreID string, meta BatchEntry, masterKey []byte) (*Entry, error) {
	if err := ValidateRestoreID(restoreID); err != nil {
		return nil, err
	}
	if err := validateBatchEntry(meta); err != nil {
		return nil, err
	}
	path := filepath.Join(paths.RecoveredBatchEntriesDir(identityID, restoreID), meta.EntryFile)
	return loadEntryAt(path, restoreID, meta, masterKey)
}

func loadEntryAt(path, restoreID string, meta BatchEntry, masterKey []byte) (*Entry, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("read recovered entry %q: %w", meta.Selector, err)
	}
	plaintext, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt recovered entry %q: %w", meta.Selector, err)
	}
	defer crypto.ZeroBytes(plaintext)
	sum := sha256.Sum256(plaintext)
	if hex.EncodeToString(sum[:]) != meta.EntrySHA256 {
		return nil, fmt.Errorf("recovered entry digest mismatch for %q", meta.Selector)
	}
	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		entry.ZeroSecrets()
		return nil, fmt.Errorf("parse recovered entry %q: %w", meta.Selector, err)
	}
	if err := validateEntry(&entry, restoreID); err != nil {
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
	if err := validateArchiveName(batch.ArchiveName); err != nil {
		return err
	}
	if !sha256Shape.MatchString(batch.ArchiveSHA256) {
		return fmt.Errorf("invalid recovered batch archive_sha256")
	}
	switch batch.SourceNodeRole {
	case string(noderole.RoleSigner), string(noderole.RoleSentry), SourceNodeRoleUnknown:
	default:
		return fmt.Errorf("invalid recovered batch source_node_role %q", batch.SourceNodeRole)
	}
	switch batch.SourcePolicyStatus {
	case SourcePolicyMissing:
		if batch.SourcePolicySHA256 != "" || len(batch.SourcePolicyYAML) != 0 {
			return fmt.Errorf("missing source policy must not include policy data")
		}
	case SourcePolicyUnverified, SourcePolicyInvalid:
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
	// Source context is authenticated by the archive's sealed manifest
	// before it ever reaches a batch, so there is no trust state to carry:
	// values are either recorded and valid, or not recorded at all.
	if batch.SourceUserAutoApprove != nil || len(batch.SourceGenesisHashMappings) > 0 {
		if err := sourcecontext.ValidateProjection(
			noderole.Role(batch.SourceNodeRole),
			sourcecontext.Projection{
				UserAutoApprove:     batch.SourceUserAutoApprove,
				GenesisHashMappings: batch.SourceGenesisHashMappings,
			},
		); err != nil {
			return fmt.Errorf("validate recovered batch source settings: %w", err)
		}
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

func validateArchiveName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > maxArchiveNameBytes ||
		filepath.Base(name) != name || strings.ContainsAny(name, `/\`+"\x00") {
		return fmt.Errorf("recovered batch archive_name must be a base filename")
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
	if !sha256Shape.MatchString(entry.EntrySHA256) {
		return fmt.Errorf("invalid recovered entry digest for %q", entry.Selector)
	}
	return nil
}

func validateEntry(entry *Entry, restoreID string) error {
	if entry == nil {
		return fmt.Errorf("recovered entry is nil")
	}
	if entry.Schema != EntrySchema {
		return fmt.Errorf("unsupported recovered entry schema %q", entry.Schema)
	}
	if err := ValidateRestoreID(entry.RestoreID); err != nil {
		return err
	}
	if entry.RestoreID != restoreID {
		return fmt.Errorf("recovered entry restore ID mismatch: batch=%s entry=%s", restoreID, entry.RestoreID)
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
	if len(entry.TemplateYAML) > 0 {
		switch templatestore.TemplateType(entry.TemplateType) {
		case templatestore.TemplateTypeGeneric, templatestore.TemplateTypeComposed:
		default:
			return fmt.Errorf("unsupported recovered entry template_type %q", entry.TemplateType)
		}
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

func syncRegularFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return file.Sync()
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
