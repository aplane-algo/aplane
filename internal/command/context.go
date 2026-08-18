// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

// Context provides command handlers with access to REPL state (serializable for plugins)
type Context struct {
	Network  string
	AlgodURL string

	SignerURL   string
	IsConnected bool

	Aliases   map[string]string
	WriteMode bool
	Simulate  bool

	WorkingDir string

	// RawArgs contains the raw argument string before quote-stripping.
	// Used by commands like 'js' that need to preserve quotes in their input.
	RawArgs string

	Internal *InternalContext
}

// InternalContext holds non-serializable state (not sent to plugins)
type InternalContext struct {
	REPLState interface{}
}
