// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/manager"
	"github.com/aplane-algo/aplane/internal/scripting"
	"github.com/aplane-algo/aplane/internal/util"
)

// REPLState holds the global state for the REPL.
// It wraps an Engine (the single source of truth for business logic state)
// and adds UI-specific state that doesn't belong in the Engine.
//
// All shared state (caches, network, clients) is accessed via r.Engine.X
// This eliminates duplicate state and manual synchronization.
type REPLState struct {
	// Core Engine (single source of truth for business logic state)
	// Access caches, network, clients via: r.Engine.Network, r.Engine.AliasCache, etc.
	Engine *engine.Engine

	// Data directory (for config file location)
	DataDir string

	// Configuration (for network restrictions, connection defaults, etc.)
	Config util.Config

	// UI-specific state (not shared with Engine)
	CommandRegistry *command.Registry // Command registry for plugin-ready command system
	PluginManager   *manager.Manager  // External plugin manager

	// JavaScript runner (persistent across js commands for state preservation)
	JSRunner scripting.Runner

	// LineReader for multi-line input in REPL (set by repl.go after readline init)
	LineReader func() (string, error)

	// SetPrompt changes the readline prompt (set by repl.go after readline init)
	SetPrompt func(string)

	// Last executed/generated script (for jssave command)
	LastScript       string // The script code
	LastScriptSource string // "js", "ai", or "file:<path>"
}

// NewREPLState creates a new REPLState with an initialized Engine.
// The Engine becomes the single source of truth for all shared state.
func NewREPLState(network string, config *util.Config) (*REPLState, error) {
	eng, err := engine.NewInitializedEngine(network, config)
	if err != nil {
		return nil, err
	}

	state := &REPLState{
		Engine: eng,
	}

	return state, nil
}

// FormatAddress formats an address for display, with optional alias
func (r *REPLState) FormatAddress(address string, authAddress string) string {
	// Auto-refresh SignerCache if connected but cache is empty
	r.Engine.EnsureSignerCache()
	return r.Engine.AliasCache.FormatAddress(address, &r.Engine.SignerCache, &r.Engine.AuthCache, authAddress)
}

// GetConnectionIndicator returns an indicator used in display, for connection state
func (r *REPLState) GetConnectionIndicator() string {
	if r.Engine.SignerClient != nil {
		return ""
	}
	return "(disc) "
}

// GetModeFlags returns short flags for active modes, shown in the prompt.
// "s" for simulate, "w" for write mode.
func (r *REPLState) GetModeFlags() string {
	flags := ""
	if r.Engine.Simulate {
		flags += "s"
	}
	if r.Engine.WriteMode {
		flags += "w"
	}
	if flags != "" {
		return " " + flags
	}
	return ""
}

// NewAddressResolver creates an AddressResolver with the signer provider configured.
// This enables @signers as a dynamic set in address resolution.
func (r *REPLState) NewAddressResolver() *util.AddressResolver {
	return r.Engine.NewAddressResolver()
}
