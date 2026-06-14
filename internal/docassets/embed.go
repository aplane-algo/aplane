// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package docassets

import (
	"embed"
	"io/fs"
)

// UserJSAPI is generated at build/test time by copying docs/USER_JSAPI.md into
// internal/docassets/generated/USER_JSAPI.md via the Makefile.
//
//go:embed generated/USER_JSAPI.md
var UserJSAPI string

// UserMCPManual is generated at build/test time by copying docs/USER_MCP_MANUAL.md
// into internal/docassets/generated/USER_MCP_MANUAL.md via the Makefile.
//
//go:embed generated/USER_MCP_MANUAL.md
var UserMCPManual string

// docsFS holds the curated, client-facing reference docs, copied from the
// curated subset of docs/ into internal/docassets/generated/docs by the
// Makefile's compile-docassets target.
//
//go:embed generated/docs
var docsFS embed.FS

// CuratedDocs returns the embedded curated reference documentation as a
// filesystem rooted at the docs directory (so entries are plain "NAME.md").
// Returns nil if the embedded tree cannot be opened.
func CuratedDocs() fs.FS {
	sub, err := fs.Sub(docsFS, "generated/docs")
	if err != nil {
		return nil
	}
	return sub
}
