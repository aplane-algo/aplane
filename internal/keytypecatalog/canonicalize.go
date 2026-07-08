// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypecatalog

import "strings"

// Canonicalize resolves a user-supplied key type to its canonical text form.
// It normalizes whitespace and case, but does not infer a publisher namespace
// from an unqualified value. This is the shared semantic normalization used by
// both client-side generation and signer-side key/template administration, so
// the two agree on the canonical key-type string.
func Canonicalize(keyType string) string {
	return strings.ToLower(strings.TrimSpace(keyType))
}
