// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "github.com/aplane-algo/aplane/internal/keytypefmt"

// displayKeyType and keyTypePublisher escape what they return: a key type
// can come from a template file or a backup archive.
func displayKeyType(keyType string) string {
	return terminalSafe(keyType)
}

func keyTypePublisher(keyType string) string {
	return terminalSafe(keytypefmt.Publisher(keyType))
}
