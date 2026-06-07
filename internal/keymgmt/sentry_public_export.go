// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/sentry/attrefs"
)

const SentryPublicKeyExportSchema = attrefs.ExportSchema

// SentryPublicKeyExport is the public-only JSON envelope emitted when an
// operator exports the verifier input for an sentry component key.
type SentryPublicKeyExport = attrefs.ExportEnvelope

// BuildSentryPublicKeyExport validates decrypted key metadata and returns a
// deterministic public-only envelope. The selector is recomputed from the
// public key so a misnamed key file cannot produce a misleading export.
func BuildSentryPublicKeyExport(componentKey string, info *KeyFileInfo) (*SentryPublicKeyExport, error) {
	if info == nil {
		return nil, fmt.Errorf("key metadata is required")
	}
	return NewSentryPublicKeyExport(componentKey, info.Type, info.PublicKeyHex)
}

// NewSentryPublicKeyExport builds a sentry public-key envelope from raw
// metadata values.
func NewSentryPublicKeyExport(componentKey, keyType, publicKeyHex string) (*SentryPublicKeyExport, error) {
	return attrefs.NewExportEnvelope(componentKey, keyType, publicKeyHex)
}
