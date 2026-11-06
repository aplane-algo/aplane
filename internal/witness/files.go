// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"path/filepath"
	"strings"
)

// File extensions describe custody roles; both roles retain the shared witness
// identity and public-reference schema. These constants carry no private-key
// capability, so signer and client packages can use them.
const (
	AdminArtifactExtension           = ".adm"
	AdminPublicReferenceExtension    = ".adm.json"
	CosignerPublicReferenceExtension = ".cos.json"

	// Legacy extensions are accepted only when reading existing files.
	LegacyArtifactExtension        = ".wit"
	LegacyPublicReferenceExtension = ".wit.json"
)

// IsAdminArtifactPath recognizes canonical and legacy standalone admin files.
func IsAdminArtifactPath(path string) bool {
	ext := filepath.Ext(path)
	return ext == AdminArtifactExtension || ext == LegacyArtifactExtension
}

// IsAdminPublicReferencePath recognizes canonical and legacy public admin files.
func IsAdminPublicReferencePath(path string) bool {
	return strings.HasSuffix(path, AdminPublicReferenceExtension) ||
		strings.HasSuffix(path, LegacyPublicReferenceExtension)
}
