// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/attestor/attrefs"
)

const AttestorPublicKeyExportSchema = attrefs.ExportSchema

// AttestorPublicKeyExport is the public-only JSON envelope emitted when an
// operator exports the verifier input for an attestor component key.
type AttestorPublicKeyExport = attrefs.ExportEnvelope

// BuildAttestorPublicKeyExport validates decrypted key metadata and returns a
// deterministic public-only envelope. The selector is recomputed from the
// public key so a misnamed key file cannot produce a misleading export.
func BuildAttestorPublicKeyExport(componentKey string, info *KeyFileInfo) (*AttestorPublicKeyExport, error) {
	if info == nil {
		return nil, fmt.Errorf("key metadata is required")
	}
	return NewAttestorPublicKeyExport(componentKey, info.Type, info.PublicKeyHex)
}

// NewAttestorPublicKeyExport builds a sentry public-key envelope from raw
// metadata values.
func NewAttestorPublicKeyExport(componentKey, keyType, publicKeyHex string) (*AttestorPublicKeyExport, error) {
	return attrefs.NewExportEnvelope(componentKey, keyType, publicKeyHex)
}
