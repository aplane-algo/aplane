// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

// File extensions describe custody roles. Both roles share the witness key
// form, identity, and public-reference schema, so the name is what keeps an
// admin file and a cosigner file apart at a glance; it proves nothing about
// custody. These constants carry no private-key capability, so signer and
// client packages can use them.
const (
	// AdminArtifactExtension identifies an encrypted standalone admin key,
	// owned by aprekey and never a signer store resident.
	AdminArtifactExtension = ".adm"
	// AdminPublicReferenceExtension identifies an admin key's public reference.
	AdminPublicReferenceExtension = ".adm.json"
	// CosignerPublicReferenceExtension identifies a cosigner key's public
	// reference: the store sidecar beside its .cos credential and the export
	// made from it.
	CosignerPublicReferenceExtension = ".cos.json"
)
