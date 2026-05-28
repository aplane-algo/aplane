// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
)

// KeyPayloadMetadata is the normalized non-secret metadata projection of a
// decrypted key payload. Parameters and bytecode are normalized across legacy
// cosmetic aliases at this boundary.
type KeyPayloadMetadata struct {
	FormatVersion          int
	HasFormatVersion       bool
	Category               string
	Address                string
	KeyType                string
	PublicKeyHex           string
	PrivateKeyHex          string
	Parameters             map[string]string
	BytecodeHex            string
	SaltCounter            *byte
	TEALSource             string
	SigningMetadataVersion int
	BaseKeyType            string
	SigningArgs            []StoredSigningArg
	TemplateFingerprint    string
	CreatedAt              string
	HasRuntimeArgs         bool
}

// ParseKeyPayloadMetadata parses decrypted key JSON and normalizes legacy
// cosmetic aliases. It does not require the payload to be a current-format key;
// callers that need runtime compatibility should call ValidateCurrentKeyPayload.
func ParseKeyPayloadMetadata(data []byte) (KeyPayloadMetadata, error) {
	fields, err := parseKeyPayloadFields(data)
	if err != nil {
		return KeyPayloadMetadata{}, err
	}
	parameters, err := normalizedParameterFields(fields)
	if err != nil {
		return KeyPayloadMetadata{}, err
	}
	bytecodeHex, err := normalizedBytecodeHexFields(fields)
	if err != nil {
		return KeyPayloadMetadata{}, err
	}

	var raw struct {
		FormatVersion          *int               `json:"format_version"`
		Category               string             `json:"category"`
		Address                string             `json:"address"`
		KeyType                string             `json:"key_type"`
		PublicKeyHex           string             `json:"public_key"`
		PrivateKeyHex          string             `json:"private_key"`
		SaltCounter            *byte              `json:"salt_counter"`
		TEALSource             string             `json:"teal_source"`
		SigningMetadataVersion int                `json:"signing_metadata_version"`
		BaseKeyType            string             `json:"base_key_type"`
		SigningArgs            []StoredSigningArg `json:"signing_args"`
		TemplateFingerprint    string             `json:"template_fingerprint"`
		CreatedAt              string             `json:"created_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return KeyPayloadMetadata{}, fmt.Errorf("failed to parse key payload metadata: %w", err)
	}

	meta := KeyPayloadMetadata{
		Category:               raw.Category,
		Address:                raw.Address,
		KeyType:                raw.KeyType,
		PublicKeyHex:           raw.PublicKeyHex,
		PrivateKeyHex:          raw.PrivateKeyHex,
		Parameters:             parameters,
		BytecodeHex:            bytecodeHex,
		SaltCounter:            raw.SaltCounter,
		TEALSource:             raw.TEALSource,
		SigningMetadataVersion: raw.SigningMetadataVersion,
		BaseKeyType:            raw.BaseKeyType,
		SigningArgs:            raw.SigningArgs,
		TemplateFingerprint:    raw.TemplateFingerprint,
		CreatedAt:              raw.CreatedAt,
	}
	if raw.FormatVersion != nil {
		meta.FormatVersion = *raw.FormatVersion
		meta.HasFormatVersion = true
	}
	_, meta.HasRuntimeArgs = fields["runtime_args"]
	return meta, nil
}

func parseKeyPayloadFields(data []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse key payload fields: %w", err)
	}
	return fields, nil
}

func normalizedParameterFields(fields map[string]json.RawMessage) (map[string]string, error) {
	return normalizedStringMapAlias(fields, "parameters", "params")
}

func normalizedBytecodeHexFields(fields map[string]json.RawMessage) (string, error) {
	return normalizedStringAlias(fields, "lsig_bytecode", "bytecode_hex")
}

func normalizedStringMapAlias(fields map[string]json.RawMessage, canonical, alias string) (map[string]string, error) {
	canonicalValue, hasCanonical, err := decodeStringMapField(fields, canonical)
	if err != nil {
		return nil, err
	}
	aliasValue, hasAlias, err := decodeStringMapField(fields, alias)
	if err != nil {
		return nil, err
	}
	if hasCanonical && hasAlias {
		if !maps.Equal(canonicalValue, aliasValue) {
			return nil, incompatibleKeyFormat("conflicting %q and %q fields", canonical, alias)
		}
		return canonicalValue, nil
	}
	if hasCanonical {
		return canonicalValue, nil
	}
	return aliasValue, nil
}

func normalizedStringAlias(fields map[string]json.RawMessage, canonical, alias string) (string, error) {
	canonicalValue, hasCanonical, err := decodeStringField(fields, canonical)
	if err != nil {
		return "", err
	}
	aliasValue, hasAlias, err := decodeStringField(fields, alias)
	if err != nil {
		return "", err
	}
	if hasCanonical && hasAlias {
		if canonicalValue != aliasValue {
			return "", incompatibleKeyFormat("conflicting %q and %q fields", canonical, alias)
		}
		return canonicalValue, nil
	}
	if hasCanonical {
		return canonicalValue, nil
	}
	return aliasValue, nil
}

func decodeStringMapField(fields map[string]json.RawMessage, name string) (map[string]string, bool, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, false, nil
	}
	if string(raw) == "null" {
		return nil, true, nil
	}
	var value map[string]string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, true, fmt.Errorf("failed to parse key payload %q field: %w", name, err)
	}
	return value, true, nil
}

func decodeStringField(fields map[string]json.RawMessage, name string) (string, bool, error) {
	raw, ok := fields[name]
	if !ok {
		return "", false, nil
	}
	if string(raw) == "null" {
		return "", true, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("failed to parse key payload %q field: %w", name, err)
	}
	return strings.TrimSpace(value), true, nil
}
