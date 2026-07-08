// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypefmt

import (
	"strings"
	"unicode"
)

// Display returns the presentation form of a key type. Key types are displayed
// canonically; publisher namespaces are not elided.
func Display(keyType string) string {
	return keyType
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
// "publisher.family.vN".
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
