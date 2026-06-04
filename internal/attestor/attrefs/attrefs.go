// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package attrefs stores identity-scoped public attestor references used when
// generating attested account keys.
package attrefs

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

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	ExportSchema = "aplane.attestor-public-key.v1"
	RecordSchema = "aplane.attestor-public-key-ref.v1"

	// ParamAttestorName is the generation parameter that selects an imported
	// attestor reference by name.
	ParamAttestorName = "attestor"
)

var nameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

type ExportEnvelope struct {
	Schema            string `json:"schema"`
	ComponentKey      string `json:"component_key"`
	KeyType           string `json:"key_type"`
	PublicKeyEncoding string `json:"public_key_encoding"`
	PublicKeyHex      string `json:"public_key_hex"`
	PublicKeySize     int    `json:"public_key_size"`
	PublicKeySHA256   string `json:"public_key_sha256"`
}

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
}

func NormalizeName(name string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "", fmt.Errorf("attestor reference name is required")
	}
	if !nameShape.MatchString(normalized) {
		return "", fmt.Errorf("invalid attestor reference name %q: use lowercase letters, numbers, '.', '-' and '_'", name)
	}
	if strings.Contains(normalized, "..") {
		return "", fmt.Errorf("invalid attestor reference name %q: must not contain '..'", name)
	}
	return normalized, nil
}

func NewExportEnvelope(componentKey, keyType, publicKeyHex string) (*ExportEnvelope, error) {
	componentKey, err := keytypes.NormalizeComponentKeySelector(componentKey)
	if err != nil {
		return nil, fmt.Errorf("invalid component key selector: %w", err)
	}
	if !keytypes.IsAttestorComponentKeyType(keyType) {
		return nil, fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	publicKeyHex = strings.ToLower(strings.TrimSpace(publicKeyHex))
	publicKeyBytes, publicKeySHA256, err := validatePublicKey(keyType, componentKey, publicKeyHex)
	if err != nil {
		return nil, err
	}
	return &ExportEnvelope{
		Schema:            ExportSchema,
		ComponentKey:      componentKey,
		KeyType:           keyType,
		PublicKeyEncoding: "hex",
		PublicKeyHex:      publicKeyHex,
		PublicKeySize:     len(publicKeyBytes),
		PublicKeySHA256:   publicKeySHA256,
	}, nil
}

func Import(paths storepaths.Paths, identityID, name string, data []byte) (*Record, error) {
	record, err := ParseImport(name, data)
	if err != nil {
		return nil, err
	}
	if record.ImportedAt == "" {
		record.ImportedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := Put(paths, identityID, *record); err != nil {
		return nil, err
	}
	return record, nil
}

func ParseImport(name string, data []byte) (*Record, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	var env ExportEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("failed to parse attestor public-key envelope: %w", err)
	}
	if env.Schema != ExportSchema {
		return nil, fmt.Errorf("unsupported attestor public-key envelope schema %q", env.Schema)
	}
	env, err = normalizeExportEnvelope(env)
	if err != nil {
		return nil, err
	}
	return &Record{
		Schema:            RecordSchema,
		Name:              name,
		ComponentKey:      env.ComponentKey,
		KeyType:           env.KeyType,
		PublicKeyEncoding: env.PublicKeyEncoding,
		PublicKeyHex:      env.PublicKeyHex,
		PublicKeySize:     env.PublicKeySize,
		PublicKeySHA256:   env.PublicKeySHA256,
	}, nil
}

func Put(paths storepaths.Paths, identityID string, rec Record) error {
	normalized, err := normalizeRecord(rec)
	if err != nil {
		return err
	}
	path := paths.AttestorRefPath(identityID, normalized.Name)
	if err := fsutil.MkdirAll(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to create attestor reference directory: %w", err)
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode attestor reference: %w", err)
	}
	data = append(data, '\n')
	if err := fsutil.WriteFile(path, data); err != nil {
		return fmt.Errorf("failed to write attestor reference: %w", err)
	}
	return nil
}

func Get(paths storepaths.Paths, identityID, name string) (Record, bool, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Record{}, false, err
	}
	path := paths.AttestorRefPath(identityID, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("failed to read attestor reference %s: %w", name, err)
	}
	rec, err := parseRecord(data, name)
	if err != nil {
		return Record{}, false, fmt.Errorf("invalid attestor reference %s: %w", name, err)
	}
	return rec, true, nil
}

func List(paths storepaths.Paths, identityID string) ([]Record, error) {
	dir := paths.AttestorRefsDir(identityID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read attestor reference directory: %w", err)
	}
	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		rec, ok, err := Get(paths, identityID, name)
		if err != nil || !ok {
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
	if err := os.Remove(paths.AttestorRefPath(identityID, name)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to remove attestor reference %s: %w", name, err)
	}
	return true, nil
}

func ResolveCreationParams(paths storepaths.Paths, identityID, keyType string, params map[string]string) (map[string]string, error) {
	if !keytypes.IsAttestedAccountKeyType(keyType) {
		return params, nil
	}
	name, hasName := params[ParamAttestorName]
	if !hasName || strings.TrimSpace(name) == "" {
		return params, nil
	}
	if _, hasPublicKey := params[keytypes.ParameterAttestorPublicKey]; hasPublicKey {
		return nil, fmt.Errorf("specify either %s or %s, not both", ParamAttestorName, keytypes.ParameterAttestorPublicKey)
	}
	rec, ok, err := Get(paths, identityID, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("attestor reference %q not found", strings.TrimSpace(name))
	}
	wantKeyType, ok := keytypes.AttestorComponentKeyTypeForAttestedAccount(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %q is not an attested account key type", keyType)
	}
	if rec.KeyType != wantKeyType {
		return nil, fmt.Errorf("attestor reference %q uses %s, but %s requires %s", rec.Name, rec.KeyType, keyType, wantKeyType)
	}

	resolved := make(map[string]string, len(params))
	for k, v := range params {
		if k == ParamAttestorName {
			continue
		}
		resolved[k] = v
	}
	resolved[keytypes.ParameterAttestorPublicKey] = rec.PublicKeyHex
	return resolved, nil
}

func normalizeExportEnvelope(env ExportEnvelope) (ExportEnvelope, error) {
	if env.PublicKeyEncoding != "" && env.PublicKeyEncoding != "hex" {
		return ExportEnvelope{}, fmt.Errorf("unsupported public_key_encoding %q", env.PublicKeyEncoding)
	}
	normalized, err := NewExportEnvelope(env.ComponentKey, env.KeyType, env.PublicKeyHex)
	if err != nil {
		return ExportEnvelope{}, err
	}
	if env.PublicKeySize != 0 && env.PublicKeySize != normalized.PublicKeySize {
		return ExportEnvelope{}, fmt.Errorf("public_key_size %d does not match decoded public key size %d", env.PublicKeySize, normalized.PublicKeySize)
	}
	if env.PublicKeySHA256 != "" && strings.ToLower(env.PublicKeySHA256) != normalized.PublicKeySHA256 {
		return ExportEnvelope{}, fmt.Errorf("public_key_sha256 does not match public_key_hex")
	}
	return *normalized, nil
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
	env, err := normalizeExportEnvelope(ExportEnvelope{
		Schema:            ExportSchema,
		ComponentKey:      rec.ComponentKey,
		KeyType:           rec.KeyType,
		PublicKeyEncoding: rec.PublicKeyEncoding,
		PublicKeyHex:      rec.PublicKeyHex,
		PublicKeySize:     rec.PublicKeySize,
		PublicKeySHA256:   rec.PublicKeySHA256,
	})
	if err != nil {
		return Record{}, err
	}
	return Record{
		Schema:            RecordSchema,
		Name:              name,
		ComponentKey:      env.ComponentKey,
		KeyType:           env.KeyType,
		PublicKeyEncoding: env.PublicKeyEncoding,
		PublicKeyHex:      env.PublicKeyHex,
		PublicKeySize:     env.PublicKeySize,
		PublicKeySHA256:   env.PublicKeySHA256,
		ImportedAt:        strings.TrimSpace(rec.ImportedAt),
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
	wantSize, ok := keytypes.ComponentPublicKeySize(keyType)
	if !ok {
		return nil, "", fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	if len(publicKeyBytes) != wantSize {
		return nil, "", fmt.Errorf("component public key length %d invalid (expected %d bytes)", len(publicKeyBytes), wantSize)
	}
	derivedSelector, err := keytypes.ComponentKeySelector(keyType, publicKeyBytes)
	if err != nil {
		return nil, "", err
	}
	if derivedSelector != componentKey {
		return nil, "", fmt.Errorf("component key selector %q does not match public key-derived selector %q", componentKey, derivedSelector)
	}
	sum := sha256.Sum256(publicKeyBytes)
	return publicKeyBytes, hex.EncodeToString(sum[:]), nil
}
