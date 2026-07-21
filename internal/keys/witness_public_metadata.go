// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

const WitnessPublicMetadataSuffix = ".wit.json"

// WitnessPublicMetadataPath returns the public-only metadata sidecar path for
// a signer-custodied witness key.
func WitnessPublicMetadataPath(paths storepaths.Paths, identityID, witnessKeyID string) string {
	return filepath.Join(paths.KeysDir(identityID), witnessKeyID+WitnessPublicMetadataSuffix)
}

// ReadWitnessPublicMetadata reads and validates a witness public metadata
// sidecar. The boolean is false when the sidecar is absent.
func ReadWitnessPublicMetadata(paths storepaths.Paths, identityID, witnessKeyID string) (sentryrefs.ExportEnvelope, bool, error) {
	witnessKeyID, err := witness.NormalizeID(witnessKeyID)
	if err != nil {
		return sentryrefs.ExportEnvelope{}, false, err
	}
	path := WitnessPublicMetadataPath(paths, identityID, witnessKeyID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sentryrefs.ExportEnvelope{}, false, nil
		}
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("failed to read witness public metadata %s: %w", path, err)
	}
	normalized, err := witness.ParsePublicReference(data)
	if err != nil {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("invalid witness public metadata %s: %w", path, err)
	}
	if normalized.WitnessKeyID != witnessKeyID {
		return sentryrefs.ExportEnvelope{}, false, fmt.Errorf("witness public metadata %s ID %q does not match %q", path, normalized.WitnessKeyID, witnessKeyID)
	}
	return normalized, true, nil
}

// WriteWitnessPublicMetadataFromKeyJSON writes the public-only sidecar for a
// restored signer-custodied witness payload. Other payloads are ignored.
func WriteWitnessPublicMetadataFromKeyJSON(paths storepaths.Paths, identityID, address string, keyJSON []byte) (string, bool, error) {
	payload, err := ParsePayload(keyJSON)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse key payload for witness public metadata: %w", err)
	}
	defer payload.ZeroSecrets()
	if payload.Category != CategoryWitness || !witness.IsKeyType(payload.KeyType) {
		return "", false, nil
	}
	if err := writeWitnessPublicMetadataFromPayload(paths, identityID, address, payload); err != nil {
		return "", false, err
	}
	witnessKeyID, err := witness.NormalizeID(address)
	if err != nil {
		return "", false, err
	}
	return WitnessPublicMetadataPath(paths, identityID, witnessKeyID), true, nil
}

func writeWitnessPublicMetadataFromPayload(paths storepaths.Paths, identityID, selector string, payload *Payload) error {
	if payload == nil || payload.Category != CategoryWitness || !witness.IsKeyType(payload.KeyType) {
		return nil
	}
	witnessKeyID, err := witness.NormalizeID(selector)
	if err != nil {
		return err
	}
	env, err := sentryrefs.NewExportEnvelope(witnessKeyID, payload.KeyType, hex.EncodeToString(payload.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to build witness public metadata: %w", err)
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode witness public metadata: %w", err)
	}
	data = append(data, '\n')
	path := WitnessPublicMetadataPath(paths, identityID, witnessKeyID)
	if err := fsutil.WriteFile(path, data); err != nil {
		return fmt.Errorf("failed to write witness public metadata %s: %w", path, err)
	}
	return nil
}
