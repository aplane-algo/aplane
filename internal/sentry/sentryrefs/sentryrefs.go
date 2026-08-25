// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sentryrefs stores product-store public sentry references used when
// generating guarded account keys.
package sentryrefs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	ExportSchema = witness.PublicReferenceSchema
	RecordSchema = "aplane.sentry-public-key-ref.v2"

	MigrationOriginV1ClientDiscovery = "v1_client_discovery"

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
	ImportedAt        string `json:"imported_at"`
	MigrationOrigin   string `json:"migration_origin,omitempty"`
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

func NewExportEnvelope(componentKey, keyType, publicKeyHex string) (*ExportEnvelope, error) {
	reference, err := witness.NewPublicReference(keyType, componentKey, strings.ToLower(strings.TrimSpace(publicKeyHex)))
	if err != nil {
		return nil, err
	}
	return &reference, nil
}

func Import(paths storepaths.Paths, name string, data []byte) (*Record, error) {
	record, err := ParseImport(name, data)
	if err != nil {
		return nil, err
	}
	existing, found, err := Get(paths, record.Name)
	if err != nil {
		return nil, err
	}
	if found {
		if sameReferenceAuthority(existing, *record) {
			return &existing, nil
		}
		return nil, fmt.Errorf(
			"sentry reference %q already exists with Witness Key ID %s; remove it explicitly before importing Witness Key ID %s",
			record.Name, existing.ComponentKey, record.ComponentKey,
		)
	}
	if record.ImportedAt == "" {
		record.ImportedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := putRecord(paths, *record); err != nil {
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
	}, nil
}

func putRecord(paths storepaths.Paths, rec Record) error {
	normalized, err := normalizeRecord(rec)
	if err != nil {
		return err
	}
	path := paths.SentryRefPath(normalized.Name)
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

func Get(paths storepaths.Paths, name string) (Record, bool, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Record{}, false, err
	}
	path := paths.SentryRefPath(name)
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

// List returns every independently valid sentry reference. A malformed record
// is omitted rather than hiding unrelated generation choices; direct Get of
// that record still returns its validation error.
func List(paths storepaths.Paths) ([]Record, error) {
	dir := paths.SentryRefsDir()
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
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read sentry reference %s: %w", name, err)
		}
		rec, err := parseRecord(data, name)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func Delete(paths storepaths.Paths, name string) (bool, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return false, err
	}
	if err := os.Remove(paths.SentryRefPath(name)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to remove sentry reference %s: %w", name, err)
	}
	return true, nil
}

func ResolveCreationParams(paths storepaths.Paths, keyType string, params map[string]string) (map[string]string, error) {
	if !keytypes.IsGuardedAccountKeyType(keyType) {
		return params, nil
	}
	wantKeyType, ok := keytypes.SentryComponentKeyTypeForGuardedAccount(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %q is not a guarded account key type", keyType)
	}
	return ResolveCreationParamsForComponent(paths, keyType, wantKeyType, params)
}

// ResolveCreationParamsForComponent resolves the signer-facing sentry selector
// for any provider that declares a sentry component type. This keeps generic
// bounded-sentry templates out of hard-coded guarded-account key-type tables.
func ResolveCreationParamsForComponent(paths storepaths.Paths, keyType, componentKeyType string, params map[string]string) (map[string]string, error) {
	selector, hasSelector := params[ParamSentryName]
	if !hasSelector || strings.TrimSpace(selector) == "" {
		return params, nil
	}
	if _, hasPublicKey := params[keytypes.ParameterSentryPublicKey]; hasPublicKey {
		return nil, fmt.Errorf("specify either %s or %s, not both", ParamSentryName, keytypes.ParameterSentryPublicKey)
	}
	rec, ok, err := resolveByNameOrComponentKey(paths, selector)
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

func resolveByNameOrComponentKey(paths storepaths.Paths, value string) (Record, bool, error) {
	value = strings.TrimSpace(value)
	if componentKey, err := witness.NormalizeID(value); err == nil {
		records, err := List(paths)
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
	return Get(paths, value)
}

func parseRecord(data []byte, expectedName string) (Record, error) {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return Record{}, fmt.Errorf("failed to parse record: %w", err)
	}
	var rec Record
	switch header.Schema {
	case recordSchemaV1:
		legacy, err := decodeRecordV1(data)
		if err != nil {
			return Record{}, err
		}
		rec, err = recordFromV1(legacy)
		if err != nil {
			return Record{}, err
		}
	case RecordSchema:
		if err := decodeRecordStrict(data, &rec); err != nil {
			return Record{}, err
		}
	default:
		return Record{}, fmt.Errorf("unsupported schema %q", header.Schema)
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

func decodeRecordStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("failed to parse record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("failed to parse record: multiple JSON values")
		}
		return fmt.Errorf("failed to parse record: %w", err)
	}
	return nil
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
	migrationOrigin := strings.TrimSpace(rec.MigrationOrigin)
	if migrationOrigin != "" && migrationOrigin != MigrationOriginV1ClientDiscovery {
		return Record{}, fmt.Errorf("unsupported sentry reference migration_origin %q", migrationOrigin)
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
		ImportedAt:        strings.TrimSpace(rec.ImportedAt),
		MigrationOrigin:   migrationOrigin,
	}, nil
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
