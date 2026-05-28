// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "strings"

func commandRawArgs(cmdName, raw string) string {
	raw = strings.TrimSpace(raw)
	if cmdName == "" || raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, cmdName) {
		return ""
	}
	if len(raw) == len(cmdName) {
		return ""
	}
	next := raw[len(cmdName)]
	if next != ' ' && next != '\t' {
		return ""
	}
	return strings.TrimSpace(raw[len(cmdName):])
}
