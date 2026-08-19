// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

const WitnessPublicMetadataSuffix = ".wit.json"

// WitnessPublicMetadataPath returns the public-only metadata sidecar path for
// a signer-custodied witness key.
func WitnessPublicMetadataPath(paths storepaths.Paths, witnessKeyID string) string {
	return WitnessPublicMetadataPathActive(mustResolveActive(paths), witnessKeyID)
}

// WitnessPublicMetadataPathActive is WitnessPublicMetadataPath against
// resolved active-store paths.
func WitnessPublicMetadataPathActive(active storepaths.ActivePaths, witnessKeyID string) string {
	return filepath.Join(active.KeysDir(), witnessKeyID+WitnessPublicMetadataSuffix)
}

// ReadWitnessPublicMetadata reads and validates a witness public metadata
// sidecar. The boolean is false when the sidecar is absent.
func ReadWitnessPublicMetadata(paths storepaths.Paths, witnessKeyID string) (sentryrefs.ExportEnvelope, bool, error) {
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		return sentryrefs.ExportEnvelope{}, false, err
	}
	return ReadWitnessPublicMetadataActive(active, witnessKeyID)
}

// ReadWitnessPublicMetadataActive is ReadWitnessPublicMetadata against
// resolved active-store paths.
func ReadWitnessPublicMetadataActive(active storepaths.ActivePaths, witnessKeyID string) (sentryrefs.ExportEnvelope, bool, error) {
	witnessKeyID, err := witness.NormalizeID(witnessKeyID)
	if err != nil {
		return sentryrefs.ExportEnvelope{}, false, err
	}
	path := WitnessPublicMetadataPathActive(active, witnessKeyID)
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

// validateWitnessPublicMetadataFilename validates a .wit.json sidecar in
// place during key scan: the filename must carry a canonical Witness Key ID,
// and the content must be a well-formed public reference whose embedded ID
// matches the filename. This mirrors what ReadWitnessPublicMetadataActive
// enforces at read time, so a generation cannot commit a sidecar that its
// own consumers would later reject.
func validateWitnessPublicMetadataFilename(path string) error {
	base := strings.TrimSuffix(filepath.Base(path), WitnessPublicMetadataSuffix)
	witnessKeyID, err := witness.NormalizeID(base)
	if err != nil {
		return fmt.Errorf("filename: %w", err)
	}
	data, _, err := fsutil.ReadRegularFile(path)
	if err != nil {
		return err
	}
	normalized, err := witness.ParsePublicReference(data)
	if err != nil {
		return err
	}
	if normalized.WitnessKeyID != witnessKeyID {
		return fmt.Errorf("embedded witness key ID %q does not match filename %q", normalized.WitnessKeyID, witnessKeyID)
	}
	return nil
}

// WriteWitnessPublicMetadataFromKeyJSONActive is
// WriteWitnessPublicMetadataFromKeyJSON against resolved active-store paths.
func WriteWitnessPublicMetadataFromKeyJSONActive(active storepaths.ActivePaths, address string, keyJSON []byte) (string, bool, error) {
	payload, err := ParsePayload(keyJSON)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse key payload for witness public metadata: %w", err)
	}
	defer payload.ZeroSecrets()
	if payload.Category != CategoryWitness || !witness.IsKeyType(payload.KeyType) {
		return "", false, nil
	}
	if err := writeWitnessPublicMetadataFromPayload(active, address, payload); err != nil {
		return "", false, err
	}
	witnessKeyID, err := witness.NormalizeID(address)
	if err != nil {
		return "", false, err
	}
	return WitnessPublicMetadataPathActive(active, witnessKeyID), true, nil
}

func writeWitnessPublicMetadataFromPayload(active storepaths.ActivePaths, selector string, payload *Payload) error {
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
	path := WitnessPublicMetadataPathActive(active, witnessKeyID)
	if err := fsutil.WriteFileDurable(path, data); err != nil {
		return fmt.Errorf("failed to write witness public metadata %s: %w", path, err)
	}
	return nil
}
