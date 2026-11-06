// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package retired exposes the KeyType Library templates that have left the
// default library but still back existing accounts.
package retired

import "embed"

// FS contains the retired plaintext KeyType Library YAML files.
//
//go:embed *.yaml
var FS embed.FS

// ReadFile reads one retired KeyType Library YAML file by basename.
func ReadFile(name string) ([]byte, error) {
	return FS.ReadFile(name)
}
