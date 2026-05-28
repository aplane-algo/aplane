// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypefmt

import (
	"strings"
	"unicode"
)

// Display returns the presentation form of a key type.
// Key types are displayed canonically to avoid ambiguity between publishers.
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

func splitCanonical(keyType string) (publisher, familyVersion string, ok bool) {
	firstDot := strings.IndexByte(keyType, '.')
	lastDot := strings.LastIndexByte(keyType, '.')
	if firstDot <= 0 || lastDot <= firstDot+1 || lastDot == len(keyType)-1 {
		return "", "", false
	}
	if !isVersionSegment(keyType[lastDot+1:]) {
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
