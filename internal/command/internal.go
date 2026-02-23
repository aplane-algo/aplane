// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

// InternalHandler wraps a Go function as a command Handler.
// The function receives args and a Context (which contains RawArgs, network info, etc.)
type InternalHandler struct {
	fn func(args []string, ctx interface{}) error
}

// NewInternalHandler creates a handler for internal Go functions.
func NewInternalHandler(fn func([]string, interface{}) error) *InternalHandler {
	return &InternalHandler{fn: fn}
}

// Execute implements the Handler interface
func (h *InternalHandler) Execute(args []string, ctx *Context) error {
	return h.fn(args, ctx)
}
