// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

import (
	"io"
	"os"
)

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
	out       io.Writer
}

// SetOut sets the output writer on the internal context.
func (ic *InternalContext) SetOut(w io.Writer) {
	ic.out = w
}

// Out returns the output writer for command output.
// Returns os.Stdout if not set.
func (ctx *Context) Out() io.Writer {
	if ctx.Internal == nil || ctx.Internal.out == nil {
		return os.Stdout
	}
	return ctx.Internal.out
}
