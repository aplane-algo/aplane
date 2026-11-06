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

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

const WitnessPublicMetadataSuffix = witness.PublicReferenceExtension

// IsWitnessPublicMetadataFilename includes the legacy public sidecars so an
// existing generation can still be validated, rotated, and rolled back.
func IsWitnessPublicMetadataFilename(name string) bool {
	return strings.HasSuffix(name, WitnessPublicMetadataSuffix) ||
		strings.HasSuffix(name, witness.LegacyPublicReferenceExtension)
}

// WitnessPublicMetadataPathActive returns the public-only metadata sidecar
// path for a signer-custodied witness key.
func WitnessPublicMetadataPathActive(active storepaths.ActivePaths, witnessKeyID string) string {
	return filepath.Join(active.KeysDir(), witnessKeyID+WitnessPublicMetadataSuffix)
}

// ReadWitnessPublicMetadataActive reads and validates a witness public
// metadata sidecar. The boolean is false when the sidecar is absent.
func ReadWitnessPublicMetadataActive(active storepaths.ActivePaths, witnessKeyID string) (cosignerrefs.ExportEnvelope, bool, error) {
	witnessKeyID, err := witness.NormalizeID(witnessKeyID)
	if err != nil {
		return cosignerrefs.ExportEnvelope{}, false, err
	}
	path := WitnessPublicMetadataPathActive(active, witnessKeyID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		path = filepath.Join(active.KeysDir(), witnessKeyID+witness.LegacyPublicReferenceExtension)
		data, err = os.ReadFile(path)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return cosignerrefs.ExportEnvelope{}, false, nil
		}
		return cosignerrefs.ExportEnvelope{}, false, fmt.Errorf("failed to read cosigner public metadata %s: %w", path, err)
	}
	normalized, err := witness.ParsePublicReference(data)
	if err != nil {
		return cosignerrefs.ExportEnvelope{}, false, fmt.Errorf("invalid cosigner public metadata %s: %w", path, err)
	}
	if normalized.WitnessKeyID != witnessKeyID {
		return cosignerrefs.ExportEnvelope{}, false, fmt.Errorf("cosigner public metadata %s ID %q does not match %q", path, normalized.WitnessKeyID, witnessKeyID)
	}
	return normalized, true, nil
}

// validateWitnessPublicMetadataFilename validates a .cos.json or legacy .wit.json sidecar in
// place during key scan: the filename must carry a canonical Witness Key ID,
// and the content must be a well-formed public reference whose embedded ID
// matches the filename. This mirrors what ReadWitnessPublicMetadataActive
// enforces at read time, so a generation cannot commit a sidecar that its
// own consumers would later reject.
func validateWitnessPublicMetadataFilename(path string) error {
	base, canonical := strings.CutSuffix(filepath.Base(path), WitnessPublicMetadataSuffix)
	if !canonical {
		base = strings.TrimSuffix(base, witness.LegacyPublicReferenceExtension)
	}
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
		return fmt.Errorf("embedded cosigner key ID %q does not match filename %q", normalized.WitnessKeyID, witnessKeyID)
	}
	return nil
}

// WriteWitnessPublicMetadataFromKeyJSONActive is
// WriteWitnessPublicMetadataFromKeyJSON against resolved active-store paths.
func WriteWitnessPublicMetadataFromKeyJSONActive(active storepaths.ActivePaths, address string, keyJSON []byte) (string, bool, error) {
	payload, err := ParsePayload(keyJSON)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse key payload for cosigner public metadata: %w", err)
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
	env, err := cosignerrefs.NewExportEnvelope(witnessKeyID, payload.KeyType, hex.EncodeToString(payload.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to build cosigner public metadata: %w", err)
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode cosigner public metadata: %w", err)
	}
	data = append(data, '\n')
	path := WitnessPublicMetadataPathActive(active, witnessKeyID)
	if err := fsutil.WriteFileDurable(path, data); err != nil {
		return fmt.Errorf("failed to write cosigner public metadata %s: %w", path, err)
	}
	return nil
}
