// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypefmt

import (
	"strings"
	"unicode"
)

// DefaultPublisher is elided from a key type's display form and is implied when
// an unqualified (publisher-less) key type is resolved back to canonical form.
const DefaultPublisher = "aplane"

// Display returns the presentation form of a key type. The default publisher is
// elided, so first-party key types render as "family.vN"; key types from any
// other publisher render canonically as "publisher.family.vN" to keep
// publishers unambiguous. The two shapes are distinguishable by dot count: an
// elided form always has exactly one dot, a qualified form two.
func Display(keyType string) string {
	if publisher, familyVersion, ok := splitCanonical(keyType); ok && publisher == DefaultPublisher {
		return familyVersion
	}
	return keyType
}

// Canonicalize resolves a user-supplied key type to its canonical
// "publisher.family.vN" form. It is the inverse of Display: an elided
// default-publisher form ("family.vN") is qualified with DefaultPublisher,
// while already-qualified and unrecognized forms are returned unchanged.
func Canonicalize(keyType string) string {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	if _, _, ok := splitCanonical(keyType); ok {
		return keyType // already publisher-qualified
	}
	if isElidedDefault(keyType) {
		return DefaultPublisher + "." + keyType
	}
	return keyType
}

// isElidedDefault reports whether keyType has the elided default-publisher shape
// "family.vN": exactly one dot, a non-empty family before it, and a trailing
// version segment. The single-dot requirement is what keeps it unambiguous from
// a qualified "publisher.family.vN" form, and relies on family names containing
// no dots.
func isElidedDefault(keyType string) bool {
	dot := strings.IndexByte(keyType, '.')
	if dot <= 0 || dot != strings.LastIndexByte(keyType, '.') {
		return false
	}
	return ValidSegment(keyType[:dot]) && isVersionSegment(keyType[dot+1:])
}

// Publisher returns the publisher segment of a canonical key type.
func Publisher(keyType string) string {
	publisher, _, ok := splitCanonical(keyType)
	if !ok {
		return ""
	}
	return publisher
}

// ValidSegment reports whether segment is a valid publisher or family segment.
// Segments intentionally exclude dots so canonical key types are always exactly
// "publisher.family.vN" and default-publisher display aliases are exactly
// "family.vN".
func ValidSegment(segment string) bool {
	if segment == "" {
		return false
	}
	for _, r := range segment {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func splitCanonical(keyType string) (publisher, familyVersion string, ok bool) {
	if strings.Count(keyType, ".") != 2 {
		return "", "", false
	}
	firstDot := strings.IndexByte(keyType, '.')
	lastDot := strings.LastIndexByte(keyType, '.')
	if firstDot <= 0 || lastDot <= firstDot+1 || lastDot == len(keyType)-1 {
		return "", "", false
	}
	if !isVersionSegment(keyType[lastDot+1:]) {
		return "", "", false
	}
	if !ValidSegment(keyType[:firstDot]) || !ValidSegment(keyType[firstDot+1:lastDot]) {
		return "", "", false
	}
	return keyType[:firstDot], keyType[firstDot+1:], true
}

func isVersionSegment(segment string) bool {
	if len(segment) < 2 || segment[0] != 'v' {
		return false
	}
	for _, r := range segment[1:] {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
