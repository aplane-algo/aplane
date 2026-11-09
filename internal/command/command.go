// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

import (
	"io"

	"github.com/aplane-algo/aplane/internal/cmdspec"
)

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
	Automation  AutomationPolicy  // Non-interactive execution policy
}

// Result is an already-computed command outcome with separate human and
// machine presentations. Neither presentation may execute command behavior.
type Result interface {
	RenderText(io.Writer) error
	MarshalMachine() ([]byte, error)
}

// Handler is the interface all command handlers must implement.
type Handler interface {
	Execute(args []string, ctx *Context) (Result, error)
}

// AutomationDisposition controls whether a command may be invoked through a
// non-interactive command surface such as MCP execute.
type AutomationDisposition uint8

const (
	AutomationUnspecified AutomationDisposition = iota
	AutomationStructured
	AutomationBlocked
)

// AutomationPolicy is attached to a primary command. Aliases resolve to that
// command and therefore inherit the same policy.
type AutomationPolicy struct {
	Disposition AutomationDisposition
	Reason      string
	Guard       func(args []string) error
}

// StructuredAutomation permits non-interactive execution.
var StructuredAutomation = AutomationPolicy{Disposition: AutomationStructured}

// GuardedStructuredAutomation permits non-interactive execution when guard
// accepts the command arguments.
func GuardedStructuredAutomation(guard func([]string) error) AutomationPolicy {
	return AutomationPolicy{Disposition: AutomationStructured, Guard: guard}
}

// BlockedAutomation rejects non-interactive execution with the supplied
// operator-facing reason.
func BlockedAutomation(reason string) AutomationPolicy {
	return AutomationPolicy{Disposition: AutomationBlocked, Reason: reason}
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
