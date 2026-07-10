// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const ComponentPublicMetadataSuffix = ".public.json"

// ComponentPublicMetadataPath returns the public-only metadata sidecar path for
// a sentry key.
func ComponentPublicMetadataPath(paths storepaths.Paths, identityID, componentKey string) string {
	return filepath.Join(paths.KeysDir(identityID), componentKey+ComponentPublicMetadataSuffix)
}

// ReadComponentPublicMetadata reads and validates a component public metadata
// sidecar. The boolean is false when the sidecar is absent.
func ReadComponentPublicMetadata(paths storepaths.Paths, identityID, componentKey string) (sentryrefs.ExportEnvelope, bool, error) {
	componentKey, err := keytypes.NormalizeComponentKeySelector(componentKey)
	if err != nil {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("invalid Sentry Key ID: %w", err)
	}
	path := ComponentPublicMetadataPath(paths, identityID, componentKey)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sentryrefs.ExportEnvelope{}, false, nil
		}
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("failed to read component public metadata %s: %w", path, err)
	}
	var env sentryrefs.ExportEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("failed to parse component public metadata %s: %w", path, err)
	}
	if env.Schema != sentryrefs.ExportSchema {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("component public metadata %s has unsupported schema %q", path, env.Schema)
	}
	normalized, err := sentryrefs.NewExportEnvelope(env.ComponentKey, env.KeyType, env.PublicKeyHex)
	if err != nil {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("invalid component public metadata %s: %w", path, err)
	}
	if normalized.ComponentKey != componentKey {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("component public metadata %s selector %q does not match %q", path, normalized.ComponentKey, componentKey)
	}
	return *normalized, true, nil
}

// WriteComponentPublicMetadataFromKeyJSON writes the public-only sidecar for a
// restored sentry key payload. Non-component payloads are ignored.
func WriteComponentPublicMetadataFromKeyJSON(paths storepaths.Paths, identityID, address string, keyJSON []byte) (string, bool, error) {
	payload, err := ParsePayload(keyJSON)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse key payload for component public metadata: %w", err)
	}
	defer payload.ZeroSecrets()
	if payload.Category != CategoryComponent || !keytypes.IsSentryComponentKeyType(payload.KeyType) {
		return "", false, nil
	}
	if err := writeComponentPublicMetadataFromPayload(paths, identityID, address, payload); err != nil {
		return "", false, err
	}
	componentKey, err := keytypes.NormalizeComponentKeySelector(address)
	if err != nil {
		return "", false, fmt.Errorf("invalid Sentry Key ID: %w", err)
	}
	return ComponentPublicMetadataPath(paths, identityID, componentKey), true, nil
}

func writeComponentPublicMetadataFromPayload(paths storepaths.Paths, identityID, selector string, payload *Payload) error {
	if payload == nil || payload.Category != CategoryComponent || !keytypes.IsSentryComponentKeyType(payload.KeyType) {
		return nil
	}
	componentKey, err := keytypes.NormalizeComponentKeySelector(selector)
	if err != nil {
		return fmt.Errorf("invalid Sentry Key ID: %w", err)
	}
	env, err := sentryrefs.NewExportEnvelope(componentKey, payload.KeyType, fmt.Sprintf("%x", payload.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to build component public metadata: %w", err)
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode component public metadata: %w", err)
	}
	data = append(data, '\n')
	path := ComponentPublicMetadataPath(paths, identityID, componentKey)
	if err := fsutil.WriteFile(path, data); err != nil {
		return fmt.Errorf("failed to write component public metadata %s: %w", path, err)
	}
	return nil
}
