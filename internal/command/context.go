// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

// Context carries per-invocation input a handler cannot get from its parsed
// arguments.
type Context struct {
	// RawArgs contains the raw argument string before quote-stripping.
	// Used by commands like 'js' that need to preserve quotes in their input.
	RawArgs string
}
