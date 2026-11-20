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

const WitnessPublicMetadataSuffix = witness.CosignerPublicReferenceExtension

// WitnessPublicMetadataPathActive returns the public-only metadata sidecar
// path for a signer-custodied witness key.
func WitnessPublicMetadataPathActive(active storepaths.GenPaths, witnessKeyID string) string {
	return filepath.Join(active.KeysDir(), witnessKeyID+WitnessPublicMetadataSuffix)
}

// ReadWitnessPublicMetadataActive reads and validates a witness public
// metadata sidecar. The boolean is false when the sidecar is absent.
func ReadWitnessPublicMetadataActive(active storepaths.GenPaths, witnessKeyID string) (cosignerrefs.ExportEnvelope, bool, error) {
	witnessKeyID, err := witness.NormalizeID(witnessKeyID)
	if err != nil {
		return cosignerrefs.ExportEnvelope{}, false, err
	}
	path := WitnessPublicMetadataPathActive(active, witnessKeyID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cosignerrefs.ExportEnvelope{}, false, nil
		}
		return cosignerrefs.ExportEnvelope{}, false, fmt.Errorf("failed to read witness public metadata %s: %w", path, err)
	}
	normalized, err := witness.ParsePublicReference(data)
	if err != nil {
		return cosignerrefs.ExportEnvelope{}, false, fmt.Errorf("invalid witness public metadata %s: %w", path, err)
	}
	if normalized.WitnessKeyID != witnessKeyID {
		return cosignerrefs.ExportEnvelope{}, false, fmt.Errorf("witness public metadata %s ID %q does not match %q", path, normalized.WitnessKeyID, witnessKeyID)
	}
	return normalized, true, nil
}

// validateWitnessPublicMetadataFilename validates a .cos.json sidecar in
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

// WriteWitnessPublicMetadataActive writes the public-only metadata sidecar
// of a witness credential and does nothing for any other category. The
// payload is one ParsePayload or MarshalPayload admitted, whose validation
// already ties the witness category to a witness key type.
func WriteWitnessPublicMetadataActive(active storepaths.GenPaths, selector string, payload *Payload) error {
	if payload == nil || payload.Category != CategoryWitness {
		return nil
	}
	witnessKeyID, err := witness.NormalizeID(selector)
	if err != nil {
		return err
	}
	env, err := cosignerrefs.NewExportEnvelope(witnessKeyID, payload.KeyType, hex.EncodeToString(payload.PublicKey))
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
