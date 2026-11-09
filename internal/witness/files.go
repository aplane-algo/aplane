// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

// MaxPublicReferenceBytes bounds a public reference read from a file.
const MaxPublicReferenceBytes = 16 * 1024

// CosignerPublicReferenceExtension identifies a cosigner key's public
// reference: the store sidecar beside its .cos credential and the export made
// from it. It carries no private-key capability, so signer and client packages
// can use it.
const CosignerPublicReferenceExtension = ".cos.json"
