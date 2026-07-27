// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypestate stores identity-scoped key type generation state.
//
// Records in this package control identity-local generation and discovery only.
// They are not signing authority; existing keys sign from their key files.
package keytypestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var validKeyTypeShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

type State string

const (
	StateEnabled  State = "enabled"
	StateDisabled State = "disabled"
)

type Source string

const (
	SourceYAMLGeneric  Source = "yaml_generic"
	SourceYAMLComposed Source = "yaml_composed"
	SourceCompiled     Source = "compiled"
)

// ErrKeyTypeInUse indicates that a key type cannot be removed because existing
// identity keys still depend on it.
var ErrKeyTypeInUse = errors.New("key type is in use")

type Record struct {
	KeyType     string `json:"key_type"`
	Source      Source `json:"source"`
	State       State  `json:"state"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ActivatedAt string `json:"activated_at"`
}

type InUseError struct {
	KeyType   string
	Addresses []string
}

func (e *InUseError) Error() string {
	if e == nil {
		return ErrKeyTypeInUse.Error()
	}
	return fmt.Sprintf("cannot remove key type %s: %d key(s) still use it: %s", e.KeyType, len(e.Addresses), strings.Join(e.Addresses, ", "))
}

func (e *InUseError) Unwrap() error {
	return ErrKeyTypeInUse
}

// Get reads a state record. Lock-free; safe to call from any goroutine.
//
// Return contract:
//   - (Record{}, false, nil): record file does not exist.
//   - (Record, true, nil): record file exists and parses as a valid record.
//   - (Record{}, false, error): record file exists but is empty, malformed, or
//     contains unknown source/state values. Treat this as corruption, not as an
//     absent record.
func Get(paths storepaths.Paths, identityID, keyType string) (Record, bool, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return Record{}, false, err
	}
	return GetActive(active, keyType)
}

// GetActive is Get against resolved active-store paths (generational or
// legacy); the caller resolved the layout once for the whole operation.
func GetActive(active storepaths.ActivePaths, keyType string) (Record, bool, error) {
	keyType, err := normalizeKeyType(keyType)
	if err != nil {
		return Record{}, false, err
	}
	path := active.KeyTypeRecord(keyType)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("failed to read key type state %s: %w", keyType, err)
	}
	rec, err := parseRecord(data, keyType)
	if err != nil {
		return Record{}, false, fmt.Errorf("invalid key type state %s: %w", keyType, err)
	}
	return rec, true, nil
}

// Put atomically writes a state record.
//
// CONTRACT: caller MUST hold Signer.storeMutationLocks[identityID].
func Put(paths storepaths.Paths, identityID string, rec Record) error {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return err
	}
	return PutActive(active, rec)
}

// PutActive is Put against resolved active-store paths.
//
// CONTRACT: caller MUST hold Signer.storeMutationLocks[identityID].
func PutActive(active storepaths.ActivePaths, rec Record) error {
	normalized, err := normalizeRecord(rec)
	if err != nil {
		return err
	}
	if normalized.ActivatedAt == "" {
		normalized.ActivatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	path := active.KeyTypeRecord(normalized.KeyType)
	if err := fsutil.MkdirAll(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to create key type state directory: %w", err)
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode key type state: %w", err)
	}
	data = append(data, '\n')
	// Durable, never in-place (docs/ARCH_GENERATIONS.md §4).
	if err := fsutil.WriteFileDurable(path, data); err != nil {
		return fmt.Errorf("failed to write key type state: %w", err)
	}
	return nil
}

// SetState performs a read-modify-write on the state field, preserving all
// other fields. Returns an error if no record exists for keyType.
//
// CONTRACT: caller MUST hold Signer.storeMutationLocks[identityID].
func SetState(paths storepaths.Paths, identityID, keyType string, state State) error {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return err
	}
	return SetStateActive(active, keyType, state)
}

// SetStateActive is SetState against resolved active-store paths.
//
// CONTRACT: caller MUST hold Signer.storeMutationLocks[identityID].
func SetStateActive(active storepaths.ActivePaths, keyType string, state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	rec, ok, err := GetActive(active, keyType)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("key type state not found: %s", keyType)
	}
	rec.State = state
	return PutActive(active, rec)
}

// Delete removes a state record. It is idempotent when the record is already
// absent.
//
// CONTRACT: caller MUST hold Signer.storeMutationLocks[identityID].
func Delete(paths storepaths.Paths, identityID, keyType string) error {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return err
	}
	return DeleteActive(active, keyType)
}

// DeleteActive is Delete against resolved active-store paths.
//
// CONTRACT: caller MUST hold Signer.storeMutationLocks[identityID].
func DeleteActive(active storepaths.ActivePaths, keyType string) error {
	keyType, err := normalizeKeyType(keyType)
	if err != nil {
		return err
	}
	if err := fsutil.RemoveDurable(active.KeyTypeRecord(keyType)); err != nil {
		return fmt.Errorf("failed to remove key type state %s: %w", keyType, err)
	}
	return nil
}

// List enumerates all valid state records for an identity. Lock-free.
//
// Corrupt records (empty, malformed, unknown enum values) are silently skipped;
// callers that need to alert operators about corruption use ListInvalid to
// enumerate the affected key types separately.
func List(paths storepaths.Paths, identityID string) ([]Record, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, err
	}
	return ListActive(active)
}

// ListActive is List against resolved active-store paths. Lock-free.
func ListActive(active storepaths.ActivePaths) ([]Record, error) {
	dir := active.KeyTypeRecordsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read key type states: %w", err)
	}

	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		keyType := strings.TrimSuffix(entry.Name(), ".json")
		rec, ok, err := GetActive(active, keyType)
		if err != nil || !ok {
			continue
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].KeyType < records[j].KeyType
	})
	return records, nil
}

// ListInvalid returns the key types whose state record file exists but is
// empty, malformed, or carries unknown enum values. Used by reload paths to
// populate InvalidKeyTypes buckets. Lock-free.
func ListInvalid(paths storepaths.Paths, identityID string) ([]string, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, err
	}
	return ListInvalidActive(active)
}

// ListInvalidActive is ListInvalid against resolved active-store paths.
func ListInvalidActive(active storepaths.ActivePaths) ([]string, error) {
	dir := active.KeyTypeRecordsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read key type states: %w", err)
	}

	var invalid []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		keyType := strings.TrimSuffix(entry.Name(), ".json")
		if _, _, err := GetActive(active, keyType); err != nil {
			invalid = append(invalid, keyType)
		}
	}
	sort.Strings(invalid)
	return invalid, nil
}

// ListEnabled returns the key types whose record state is StateEnabled.
// Lock-free.
func ListEnabled(paths storepaths.Paths, identityID string) ([]string, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, err
	}
	return ListEnabledActive(active)
}

// ListEnabledActive is ListEnabled against resolved active-store paths.
func ListEnabledActive(active storepaths.ActivePaths) ([]string, error) {
	if invalid, err := ListInvalidActive(active); err != nil {
		return nil, err
	} else if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid key type state records: %s", strings.Join(invalid, ", "))
	}
	records, err := ListActive(active)
	if err != nil {
		return nil, err
	}
	keyTypes := make([]string, 0, len(records))
	for _, rec := range records {
		if rec.State == StateEnabled {
			keyTypes = append(keyTypes, rec.KeyType)
		}
	}
	return keyTypes, nil
}

// RequireUnused scans existing identity keys and returns ErrKeyTypeInUse if any
// key uses keyType.
func RequireUnused(paths storepaths.Paths, identityID, keyType string, masterKey []byte) error {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return err
	}
	return RequireUnusedActive(active, keyType, masterKey)
}

// RequireUnusedActive is RequireUnused against resolved active-store paths.
func RequireUnusedActive(active storepaths.ActivePaths, keyType string, masterKey []byte) error {
	keyType, err := normalizeKeyType(keyType)
	if err != nil {
		return err
	}
	if len(masterKey) == 0 {
		return fmt.Errorf("master key is required to verify key type is unused")
	}
	scan, err := keys.ScanKeysDirectoryWithMasterKeyActive(active, masterKey)
	if err != nil {
		return err
	}
	var addresses []string
	for address, info := range scan {
		if strings.EqualFold(info.KeyType, keyType) {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil
	}
	sort.Strings(addresses)
	return &InUseError{KeyType: keyType, Addresses: addresses}
}

// CanGenerate reports whether keyType is generatable by identityID. It returns
// an error when state storage is corrupt or unreadable so callers can surface a
// storage error rather than reporting "invalid key type."
func CanGenerate(paths storepaths.Paths, identityID, keyType string) (bool, error) {
	keyType, err := normalizeKeyType(keyType)
	if err != nil {
		return false, err
	}
	if entry, ok := keytypecatalog.Get(keyType); ok && entry.Availability == keytypecatalog.AvailabilityDefaultEnabled {
		return true, nil
	}
	rec, ok, err := Get(paths, identityID, keyType)
	if err != nil {
		return false, err
	}
	return ok && rec.State == StateEnabled, nil
}

func parseRecord(data []byte, keyType string) (Record, error) {
	if len(data) == 0 {
		return Record{}, fmt.Errorf("empty record")
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, err
	}
	if rec.KeyType == "" {
		rec.KeyType = keyType
	}
	normalized, err := normalizeRecord(rec)
	if err != nil {
		return Record{}, err
	}
	if normalized.KeyType != keyType {
		return Record{}, fmt.Errorf("record key_type %q does not match filename key_type %q", normalized.KeyType, keyType)
	}
	return normalized, nil
}

func normalizeRecord(rec Record) (Record, error) {
	keyType, err := normalizeKeyType(rec.KeyType)
	if err != nil {
		return Record{}, err
	}
	rec.KeyType = keyType
	if err := validateSource(rec.Source); err != nil {
		return Record{}, err
	}
	if err := validateState(rec.State); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// NormalizeKeyType validates and canonicalizes a key type name (lowercase,
// trimmed, restricted shape). Every state record and template file is stored
// under its canonical name; strict-validation sweeps use this to reject
// namespace entries whose basename is not already canonical — the lookup
// APIs normalize before reading, so a noncanonical file would otherwise be
// silently invisible rather than reported.
func NormalizeKeyType(keyType string) (string, error) {
	return normalizeKeyType(keyType)
}

func normalizeKeyType(keyType string) (string, error) {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	if keyType == "" {
		return "", fmt.Errorf("key type is required")
	}
	if strings.Contains(keyType, "..") {
		return "", fmt.Errorf("invalid key type: %s", keyType)
	}
	if !validKeyTypeShape.MatchString(keyType) {
		return "", fmt.Errorf("invalid key type: %s", keyType)
	}
	return keyType, nil
}

func validateSource(source Source) error {
	switch source {
	case SourceYAMLGeneric, SourceYAMLComposed, SourceCompiled:
		return nil
	default:
		return fmt.Errorf("invalid key type source %q", source)
	}
}

func validateState(state State) error {
	switch state {
	case StateEnabled, StateDisabled:
		return nil
	default:
		return fmt.Errorf("invalid key type state %q", state)
	}
}
