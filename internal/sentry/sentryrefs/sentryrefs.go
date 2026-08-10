// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sentryrefs stores identity-scoped public sentry references used when
// generating guarded account keys.
package sentryrefs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	ExportSchema          = witness.PublicReferenceSchema
	RecordSchema          = "aplane.sentry-public-key-ref.v1"
	SourceManual          = "manual"
	SourceClientDiscovery = "client_discovery"

	// ParamSentryName is the generation parameter that selects an imported
	// sentry reference by name.
	ParamSentryName = "sentry"
)

var nameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

type ExportEnvelope = witness.PublicReference

type Record struct {
	Schema            string `json:"schema"`
	Name              string `json:"name"`
	ComponentKey      string `json:"component_key"`
	KeyType           string `json:"key_type"`
	PublicKeyEncoding string `json:"public_key_encoding"`
	PublicKeyHex      string `json:"public_key_hex"`
	PublicKeySize     int    `json:"public_key_size"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	Source            string `json:"source,omitempty"`
	EndpointAlias     string `json:"endpoint_alias,omitempty"`
	LastSeenAt        string `json:"last_seen_at,omitempty"`
	SyncedAt          string `json:"synced_at,omitempty"`
	ImportedAt        string `json:"imported_at"`
}

// DiscoveredRecord is a public sentry reference learned by a client endpoint
// discovery pass and synced into a signer identity for key-generation UX.
type DiscoveredRecord struct {
	EndpointAlias string
	ComponentKey  string
	KeyType       string
	PublicKeyHex  string
	LastSeenAt    string
}

// SyncResult summarizes one client-discovered sentry reference sync.
type SyncResult struct {
	Added   int
	Updated int
	Removed int
	Records []Record
}

func NormalizeName(name string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "", fmt.Errorf("sentry reference name is required")
	}
	if !nameShape.MatchString(normalized) {
		return "", fmt.Errorf("invalid sentry reference name %q: use lowercase letters, numbers, '.', '-' and '_'", name)
	}
	if strings.Contains(normalized, "..") {
		return "", fmt.Errorf("invalid sentry reference name %q: must not contain '..'", name)
	}
	return normalized, nil
}

func SyncedReferenceName(endpointAlias, componentKey string) (string, error) {
	componentKey, err := witness.NormalizeID(componentKey)
	if err != nil {
		return "", err
	}
	alias := sanitizeEndpointAlias(endpointAlias)
	return NormalizeName("endpoint-" + alias + "-" + componentKey)
}

func NewExportEnvelope(componentKey, keyType, publicKeyHex string) (*ExportEnvelope, error) {
	reference, err := witness.NewPublicReference(keyType, componentKey, strings.ToLower(strings.TrimSpace(publicKeyHex)))
	if err != nil {
		return nil, err
	}
	return &reference, nil
}

func Import(paths storepaths.Paths, identityID, name string, data []byte) (*Record, error) {
	record, err := ParseImport(name, data)
	if err != nil {
		return nil, err
	}
	existing, found, err := Get(paths, identityID, record.Name)
	if err != nil {
		return nil, err
	}
	if found {
		if sameReferenceAuthority(existing, *record) {
			if existing.Source == SourceManual {
				return &existing, nil
			}
			// An explicit import pins a previously discovered authority. Publish
			// the manual record so a later discovery sync cannot reap it merely
			// because its endpoint is no longer present.
			if record.ImportedAt == "" {
				record.ImportedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if err := Put(paths, identityID, *record); err != nil {
				return nil, err
			}
			return record, nil
		}
		return nil, fmt.Errorf(
			"sentry reference %q already exists with Witness Key ID %s; remove it explicitly before importing Witness Key ID %s",
			record.Name, existing.ComponentKey, record.ComponentKey,
		)
	}
	if record.ImportedAt == "" {
		record.ImportedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := Put(paths, identityID, *record); err != nil {
		return nil, err
	}
	return record, nil
}

func sameReferenceAuthority(a, b Record) bool {
	return a.ComponentKey == b.ComponentKey &&
		a.KeyType == b.KeyType &&
		a.PublicKeyEncoding == b.PublicKeyEncoding &&
		a.PublicKeyHex == b.PublicKeyHex &&
		a.PublicKeySize == b.PublicKeySize &&
		a.PublicKeySHA256 == b.PublicKeySHA256
}

func SyncDiscovered(paths storepaths.Paths, identityID string, discovered []DiscoveredRecord) (*SyncResult, error) {
	syncedAt := time.Now().UTC().Format(time.RFC3339)
	desired := make(map[string]Record, len(discovered))
	seenPublicKeys := map[string]string{}
	for _, item := range discovered {
		rec, err := recordFromDiscovered(item, syncedAt)
		if err != nil {
			return nil, err
		}
		if previous, ok := seenPublicKeys[rec.PublicKeyHex]; ok && previous != rec.EndpointAlias {
			return nil, fmt.Errorf("sentry public key %s appears under multiple endpoint aliases (%s and %s)", rec.PublicKeyHex, previous, rec.EndpointAlias)
		}
		seenPublicKeys[rec.PublicKeyHex] = rec.EndpointAlias
		if existing, ok := desired[rec.Name]; ok && !sameSyncedRecord(existing, rec) {
			return nil, fmt.Errorf("multiple discovered sentries resolve to reference name %q", rec.Name)
		}
		desired[rec.Name] = rec
	}

	existing, err := List(paths, identityID)
	if err != nil {
		return nil, err
	}
	existingByName := make(map[string]Record, len(existing))
	for _, rec := range existing {
		existingByName[rec.Name] = rec
	}

	result := &SyncResult{Records: make([]Record, 0, len(desired))}
	for name, rec := range desired {
		if current, ok := existingByName[name]; ok && current.Source != SourceClientDiscovery {
			return nil, fmt.Errorf("synced sentry reference %q collides with existing %s reference", name, current.Source)
		}
		if current, ok := existingByName[name]; ok {
			if !sameSyncedRecord(current, rec) {
				result.Updated++
				if err := Put(paths, identityID, rec); err != nil {
					return nil, err
				}
			} else {
				rec.SyncedAt = current.SyncedAt
				desired[name] = rec
			}
		} else {
			result.Added++
			if err := Put(paths, identityID, rec); err != nil {
				return nil, err
			}
		}
		result.Records = append(result.Records, rec)
	}

	for _, current := range existing {
		if current.Source != SourceClientDiscovery {
			continue
		}
		if _, keep := desired[current.Name]; keep {
			continue
		}
		removed, err := Delete(paths, identityID, current.Name)
		if err != nil {
			return nil, err
		}
		if removed {
			result.Removed++
		}
	}

	sort.Slice(result.Records, func(i, j int) bool {
		return result.Records[i].Name < result.Records[j].Name
	})
	return result, nil
}

func ParseImport(name string, data []byte) (*Record, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	env, err := witness.ParsePublicReference(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sentry public-key envelope: %w", err)
	}
	publicKeyBytes, publicKeySHA256, err := validatePublicKey(env.KeyType, env.WitnessKeyID, env.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	return &Record{
		Schema:            RecordSchema,
		Name:              name,
		ComponentKey:      env.WitnessKeyID,
		KeyType:           env.KeyType,
		PublicKeyEncoding: "hex",
		PublicKeyHex:      env.PublicKeyHex,
		PublicKeySize:     len(publicKeyBytes),
		PublicKeySHA256:   publicKeySHA256,
		Source:            SourceManual,
	}, nil
}

func Put(paths storepaths.Paths, identityID string, rec Record) error {
	normalized, err := normalizeRecord(rec)
	if err != nil {
		return err
	}
	path := paths.SentryRefPath(identityID, normalized.Name)
	if err := fsutil.MkdirAllPrivate(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to create sentry reference directory: %w", err)
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode sentry reference: %w", err)
	}
	data = append(data, '\n')
	if err := fsutil.WriteFile(path, data); err != nil {
		return fmt.Errorf("failed to write sentry reference: %w", err)
	}
	return nil
}

func Get(paths storepaths.Paths, identityID, name string) (Record, bool, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Record{}, false, err
	}
	path := paths.SentryRefPath(identityID, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("failed to read sentry reference %s: %w", name, err)
	}
	rec, err := parseRecord(data, name)
	if err != nil {
		return Record{}, false, fmt.Errorf("invalid sentry reference %s: %w", name, err)
	}
	return rec, true, nil
}

func List(paths storepaths.Paths, identityID string) ([]Record, error) {
	dir := paths.SentryRefsDir(identityID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read sentry reference directory: %w", err)
	}
	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		rec, ok, err := Get(paths, identityID, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func Delete(paths storepaths.Paths, identityID, name string) (bool, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return false, err
	}
	if err := os.Remove(paths.SentryRefPath(identityID, name)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to remove sentry reference %s: %w", name, err)
	}
	return true, nil
}

func ResolveCreationParams(paths storepaths.Paths, identityID, keyType string, params map[string]string) (map[string]string, error) {
	if !keytypes.IsGuardedAccountKeyType(keyType) {
		return params, nil
	}
	wantKeyType, ok := keytypes.SentryComponentKeyTypeForGuardedAccount(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %q is not a guarded account key type", keyType)
	}
	return ResolveCreationParamsForComponent(paths, identityID, keyType, wantKeyType, params)
}

// ResolveCreationParamsForComponent resolves the signer-facing sentry selector
// for any provider that declares a sentry component type. This keeps generic
// bounded-sentry templates out of hard-coded guarded-account key-type tables.
func ResolveCreationParamsForComponent(paths storepaths.Paths, identityID, keyType, componentKeyType string, params map[string]string) (map[string]string, error) {
	selector, hasSelector := params[ParamSentryName]
	if !hasSelector || strings.TrimSpace(selector) == "" {
		return params, nil
	}
	if _, hasPublicKey := params[keytypes.ParameterSentryPublicKey]; hasPublicKey {
		return nil, fmt.Errorf("specify either %s or %s, not both", ParamSentryName, keytypes.ParameterSentryPublicKey)
	}
	rec, ok, err := resolveByNameOrComponentKey(paths, identityID, selector)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("sentry reference or Witness Key ID %q not found", strings.TrimSpace(selector))
	}
	if rec.KeyType != componentKeyType {
		return nil, fmt.Errorf("sentry reference %q uses %s, but %s requires %s", rec.Name, rec.KeyType, keyType, componentKeyType)
	}

	resolved := make(map[string]string, len(params))
	for k, v := range params {
		if k == ParamSentryName {
			continue
		}
		resolved[k] = v
	}
	resolved[keytypes.ParameterSentryPublicKey] = rec.PublicKeyHex
	return resolved, nil
}

func resolveByNameOrComponentKey(paths storepaths.Paths, identityID, value string) (Record, bool, error) {
	value = strings.TrimSpace(value)
	if componentKey, err := witness.NormalizeID(value); err == nil {
		records, err := List(paths, identityID)
		if err != nil {
			return Record{}, false, err
		}
		for _, rec := range records {
			if rec.ComponentKey == componentKey {
				return rec, true, nil
			}
		}
		return Record{}, false, nil
	}
	return Get(paths, identityID, value)
}

func parseRecord(data []byte, expectedName string) (Record, error) {
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, fmt.Errorf("failed to parse record: %w", err)
	}
	if rec.Schema != RecordSchema {
		return Record{}, fmt.Errorf("unsupported schema %q", rec.Schema)
	}
	rec, err := normalizeRecord(rec)
	if err != nil {
		return Record{}, err
	}
	if rec.Name != expectedName {
		return Record{}, fmt.Errorf("record name %q does not match filename %q", rec.Name, expectedName)
	}
	return rec, nil
}

func normalizeRecord(rec Record) (Record, error) {
	name, err := NormalizeName(rec.Name)
	if err != nil {
		return Record{}, err
	}
	env, err := witness.NewPublicReference(rec.KeyType, rec.ComponentKey, rec.PublicKeyHex)
	if err != nil {
		return Record{}, err
	}
	publicKeyBytes, publicKeySHA256, err := validatePublicKey(env.KeyType, env.WitnessKeyID, env.PublicKeyHex)
	if err != nil {
		return Record{}, err
	}
	if rec.PublicKeyEncoding != "" && rec.PublicKeyEncoding != "hex" {
		return Record{}, fmt.Errorf("unsupported public_key_encoding %q", rec.PublicKeyEncoding)
	}
	if rec.PublicKeySize != 0 && rec.PublicKeySize != len(publicKeyBytes) {
		return Record{}, fmt.Errorf("public_key_size %d does not match decoded public key size %d", rec.PublicKeySize, len(publicKeyBytes))
	}
	if rec.PublicKeySHA256 != "" && strings.ToLower(rec.PublicKeySHA256) != publicKeySHA256 {
		return Record{}, fmt.Errorf("public_key_sha256 does not match public_key_hex")
	}
	source := strings.TrimSpace(rec.Source)
	if source == "" {
		source = SourceManual
	}
	switch source {
	case SourceManual:
		rec.EndpointAlias = ""
		rec.LastSeenAt = ""
		rec.SyncedAt = ""
	case SourceClientDiscovery:
		if strings.TrimSpace(rec.EndpointAlias) == "" {
			return Record{}, fmt.Errorf("endpoint_alias is required for %s sentry reference", SourceClientDiscovery)
		}
	default:
		return Record{}, fmt.Errorf("unsupported sentry reference source %q", source)
	}
	return Record{
		Schema:            RecordSchema,
		Name:              name,
		ComponentKey:      env.WitnessKeyID,
		KeyType:           env.KeyType,
		PublicKeyEncoding: "hex",
		PublicKeyHex:      env.PublicKeyHex,
		PublicKeySize:     len(publicKeyBytes),
		PublicKeySHA256:   publicKeySHA256,
		Source:            source,
		EndpointAlias:     strings.TrimSpace(rec.EndpointAlias),
		LastSeenAt:        strings.TrimSpace(rec.LastSeenAt),
		SyncedAt:          strings.TrimSpace(rec.SyncedAt),
		ImportedAt:        strings.TrimSpace(rec.ImportedAt),
	}, nil
}

func recordFromDiscovered(item DiscoveredRecord, syncedAt string) (Record, error) {
	endpointAlias := strings.TrimSpace(item.EndpointAlias)
	if endpointAlias == "" {
		return Record{}, fmt.Errorf("endpoint alias is required for discovered sentry")
	}
	componentKey, err := witness.NormalizeID(item.ComponentKey)
	if err != nil {
		return Record{}, fmt.Errorf("invalid discovered Witness Key ID: %w", err)
	}
	name, err := SyncedReferenceName(endpointAlias, componentKey)
	if err != nil {
		return Record{}, err
	}
	env, err := NewExportEnvelope(componentKey, item.KeyType, item.PublicKeyHex)
	if err != nil {
		return Record{}, err
	}
	return normalizeRecord(Record{
		Schema:            RecordSchema,
		Name:              name,
		ComponentKey:      env.WitnessKeyID,
		KeyType:           env.KeyType,
		PublicKeyEncoding: "hex",
		PublicKeyHex:      env.PublicKeyHex,
		Source:            SourceClientDiscovery,
		EndpointAlias:     endpointAlias,
		LastSeenAt:        item.LastSeenAt,
		SyncedAt:          syncedAt,
	})
}

func sameSyncedRecord(a, b Record) bool {
	return a.Name == b.Name &&
		a.ComponentKey == b.ComponentKey &&
		a.KeyType == b.KeyType &&
		a.PublicKeyEncoding == b.PublicKeyEncoding &&
		a.PublicKeyHex == b.PublicKeyHex &&
		a.PublicKeySize == b.PublicKeySize &&
		a.PublicKeySHA256 == b.PublicKeySHA256 &&
		a.Source == b.Source &&
		a.EndpointAlias == b.EndpointAlias &&
		a.LastSeenAt == b.LastSeenAt
}

func sanitizeEndpointAlias(alias string) string {
	alias = strings.ToLower(strings.TrimSpace(alias))
	var b strings.Builder
	for _, r := range alias {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "endpoint"
	}
	return out
}

func validatePublicKey(keyType, componentKey, publicKeyHex string) ([]byte, string, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, "", fmt.Errorf("public key must be hex: %w", err)
	}
	if len(publicKeyBytes) == 0 {
		return nil, "", fmt.Errorf("public key is required")
	}
	wantSize, ok := witness.PublicKeySize(keyType)
	if !ok {
		return nil, "", fmt.Errorf("key type %q is not a sentry key type", keyType)
	}
	if len(publicKeyBytes) != wantSize {
		return nil, "", fmt.Errorf("component public key length %d invalid (expected %d bytes)", len(publicKeyBytes), wantSize)
	}
	derivedSelector, err := witness.ID(keyType, publicKeyBytes)
	if err != nil {
		return nil, "", err
	}
	if derivedSelector != componentKey {
		return nil, "", fmt.Errorf("witness key ID %q does not match public key-derived Witness Key ID %q", componentKey, derivedSelector)
	}
	sum := sha256.Sum256(publicKeyBytes)
	return publicKeyBytes, hex.EncodeToString(sum[:]), nil
}
