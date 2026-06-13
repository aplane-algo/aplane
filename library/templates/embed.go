// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templates exposes bundled KeyType Library YAML files to binaries that
// need installation defaults before a signer-data library copy exists.
package templates

import "embed"

// FS contains the shipped plaintext KeyType Library YAML files.
//
//go:embed *.yaml
var FS embed.FS

// ReadFile reads one bundled KeyType Library YAML file by basename.
func ReadFile(name string) ([]byte, error) {
	return FS.ReadFile(name)
}
