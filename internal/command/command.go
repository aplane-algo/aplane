// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

import "github.com/aplane-algo/aplane/internal/cmdspec"

// Command represents a REPL command with metadata
type Command struct {
	Name        string            // Primary command name
	Aliases     []string          // Alternative names (e.g., "h" for "help")
	Usage       string            // Usage string: "send to=<addr> amount=<val>"
	Description string            // One-line description
	LongHelp    string            // Multi-line detailed help (optional)
	Category    string            // "Transaction Commands", "Setup", etc.
	IsPlugin    bool              // true = external plugin, false = internal
	Handler     Handler           // Command execution handler
	ArgSpecs    []cmdspec.ArgSpec // Argument completion specs (ordered by position)
}

// Handler is the interface all command handlers must implement
// This allows both internal Go functions and external plugins
type Handler interface {
	Execute(args []string, ctx *Context) error
}

// Category constants for organizing commands
const (
	CategorySetup         = "Setup Commands"
	CategoryTransaction   = "Transaction Commands"
	CategoryAlias         = "Alias Management"
	CategoryRekey         = "Rekey Management"
	CategoryInfo          = "Information"
	CategoryKeyMgmt       = "Key Management"
	CategoryASA           = "ASA Management"
	CategoryConfig        = "Configuration"
	CategoryVariables     = "Variables"
	CategoryAutomation    = "Automation"
	CategoryRemote        = "Remote Signing"
	CategoryOrchestration = "Orchestration" // For future expansion
)
