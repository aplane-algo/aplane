// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sentryrefs

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	recordSchemaV1          = "aplane.sentry-public-key-ref.v1"
	recordSourceManualV1    = "manual"
	recordSourceDiscoveryV1 = "client_discovery"
)

// recordV1 is the bounded read adapter for pre-v2 sentry references. Live
// discovery provenance is decoded only here and never enters the v2 runtime
// record shape.
type recordV1 struct {
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

func decodeRecordV1(data []byte) (recordV1, error) {
	var legacy recordV1
	// V1 was historically decoded with encoding/json's forward-compatible
	// unknown-field behavior. Preserve that bounded read compatibility while
	// keeping the v2 record strict.
	if err := json.Unmarshal(data, &legacy); err != nil {
		return recordV1{}, fmt.Errorf("failed to parse record: %w", err)
	}
	return legacy, nil
}

func recordFromV1(legacy recordV1) (Record, error) {
	source := strings.TrimSpace(legacy.Source)
	if source == "" {
		source = recordSourceManualV1
	}
	migrationOrigin := ""
	switch source {
	case recordSourceManualV1:
	case recordSourceDiscoveryV1:
		migrationOrigin = MigrationOriginV1ClientDiscovery
	default:
		return Record{}, fmt.Errorf("unsupported sentry reference source %q", source)
	}
	return Record{
		Schema:            RecordSchema,
		Name:              legacy.Name,
		ComponentKey:      legacy.ComponentKey,
		KeyType:           legacy.KeyType,
		PublicKeyEncoding: legacy.PublicKeyEncoding,
		PublicKeyHex:      legacy.PublicKeyHex,
		PublicKeySize:     legacy.PublicKeySize,
		PublicKeySHA256:   legacy.PublicKeySHA256,
		ImportedAt:        legacy.ImportedAt,
		MigrationOrigin:   migrationOrigin,
	}, nil
}
