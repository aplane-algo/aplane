// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

// InternalHandler wraps a result-bearing Go function as a command Handler.
// The function receives args and a Context (which contains RawArgs, network info, etc.)
type InternalHandler struct {
	fn func(args []string, ctx interface{}) (Result, error)
}

// NewInternalHandler creates a handler for an internal result-bearing function.
func NewInternalHandler(fn func([]string, interface{}) (Result, error)) *InternalHandler {
	return &InternalHandler{fn: fn}
}

// Execute implements the Handler interface
func (h *InternalHandler) Execute(args []string, ctx *Context) (Result, error) {
	return h.fn(args, ctx)
}
