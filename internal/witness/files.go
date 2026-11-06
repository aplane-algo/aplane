// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"path/filepath"
	"strings"
)

// Cosigner files share one extension across spend and admin roles. Their
// contents distinguish store encryption from standalone passphrase encryption.
// These constants carry no private-key capability, so all readers can use them.
const (
	CredentialExtension      = ".cos"
	PublicReferenceExtension = ".cos.json"

	// Legacy extensions are accepted only when reading existing files.
	LegacyArtifactExtension             = ".wit"
	LegacyPublicReferenceExtension      = ".wit.json"
	LegacyAdminArtifactExtension        = ".adm"
	LegacyAdminPublicReferenceExtension = ".adm.json"
)

// IsStandaloneCredentialPath checks the filename only. A standalone reader
// must still validate the bundle schema and reject store-encrypted contents.
func IsStandaloneCredentialPath(path string) bool {
	ext := filepath.Ext(path)
	return ext == CredentialExtension || ext == LegacyArtifactExtension || ext == LegacyAdminArtifactExtension
}

// IsPublicReferencePath recognizes public references for either cosigner role.
// Legacy admin references are accepted for operator-supplied files only;
// managed-store sidecars retain their narrower filename contract.
func IsPublicReferencePath(path string) bool {
	return strings.HasSuffix(path, PublicReferenceExtension) ||
		strings.HasSuffix(path, LegacyPublicReferenceExtension) ||
		strings.HasSuffix(path, LegacyAdminPublicReferenceExtension)
}
