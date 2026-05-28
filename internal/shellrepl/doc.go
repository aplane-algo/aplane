// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package shellrepl owns apshell's human-facing command syntax: tokenization,
// command-specific parsing, and interactive completion.
//
// It delegates reusable semantic argument parsing, such as typed addresses,
// assets, amounts, and key=value fields, to internal/cmdspec so non-REPL
// callers can share those rules without depending on cmd/apshell.
package shellrepl
