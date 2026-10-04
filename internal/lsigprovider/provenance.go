// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

// Template provenance statuses reported by CompareTemplateFingerprint.
const (
	TemplateProvenanceStatusConflict    = "conflict"
	TemplateProvenanceStatusUnavailable = "unavailable"
)

// TemplateFingerprintForKeyType returns the semantic compatibility fingerprint
// of the currently registered provider/template, when that provider exposes one.
func TemplateFingerprintForKeyType(keyType string) string {
	provider := Get(keyType)
	if provider == nil {
		return ""
	}
	fingerprint, ok := CompatibilityFingerprintOf(provider)
	if !ok {
		return ""
	}
	return fingerprint
}

// CompareTemplateFingerprint compares durable key-file template provenance with
// the provider/template currently registered in this signer process.
func CompareTemplateFingerprint(keyType, storedFingerprint string) (status, note string) {
	if storedFingerprint == "" {
		return "", ""
	}
	provider := Get(keyType)
	if provider == nil {
		return TemplateProvenanceStatusUnavailable, "creation template is not registered in this signer"
	}
	liveFingerprint, ok := CompatibilityFingerprintOf(provider)
	if !ok {
		return TemplateProvenanceStatusUnavailable, "registered key type does not expose a template fingerprint"
	}
	match, comparable := FingerprintsMatch(storedFingerprint, liveFingerprint)
	if !comparable {
		// Different fingerprint formats (a future formula version, or an
		// unparseable/legacy value) are not a behavior conflict — provenance
		// simply cannot be established across formats.
		return TemplateProvenanceStatusUnavailable, "stored template fingerprint uses an incompatible format and cannot be compared to the currently registered definition"
	}
	if !match {
		return TemplateProvenanceStatusConflict, "creation template fingerprint differs from the currently registered definition"
	}
	return "", ""
}
