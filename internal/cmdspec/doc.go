// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package cmdspec provides reusable semantic parsers for command arguments.
//
// It is intentionally below internal/shellrepl: shellrepl owns shell syntax
// and completion, while cmdspec owns reusable typed values and validation that
// command handlers, tests, and non-interactive callers can share.
package cmdspec
