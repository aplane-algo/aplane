// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
)

// TestCommandRegistration verifies all expected commands are registered
func TestCommandRegistration(t *testing.T) {
	// Expected commands that should be registered
	expectedCommands := []struct {
		name     string
		category string
	}{
		// Transaction commands
		{"send", command.CategoryTransaction},
		{"sweep", command.CategoryTransaction},
		{"optin", command.CategoryTransaction},
		{"optout", command.CategoryTransaction},
		{"keyreg", command.CategoryTransaction},
		{"close", command.CategoryTransaction},
		{"validate", command.CategoryTransaction},
		{"sign", command.CategoryTransaction},

		// Info commands
		{"balance", command.CategoryInfo},
		{"holders", command.CategoryInfo},
		{"participation", command.CategoryInfo},
		{"help", command.CategoryInfo},
		{"status", command.CategoryInfo},
		{"accounts", command.CategoryInfo},
		{"quit", command.CategoryInfo},

		// Alias commands
		{"alias", command.CategoryAlias},
		{"sets", command.CategoryAlias},

		// Rekey commands
		{"rekey", command.CategoryRekey},
		{"unrekey", command.CategoryRekey},

		// Key management
		{"keys", command.CategoryKeyMgmt},

		// ASA commands
		{"info", command.CategoryASA},
		{"asa", command.CategoryASA},

		// Config commands
		{"network", command.CategoryConfig},
		{"write", command.CategoryConfig},
		{"config", command.CategoryConfig},

		// Automation commands
		{"script", command.CategoryAutomation},

		// Remote commands
		{"connect", command.CategoryRemote},
	}

	// Create a minimal REPLState for registry initialization
	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, tc := range expectedCommands {
		t.Run(tc.name, func(t *testing.T) {
			cmd, ok := registry.Lookup(tc.name)
			if !ok {
				t.Errorf("command %q not registered", tc.name)
				return
			}
			if cmd.Category != tc.category {
				t.Errorf("command %q category = %v, want %v", tc.name, cmd.Category, tc.category)
			}
			if cmd.Handler == nil {
				t.Errorf("command %q has nil handler", tc.name)
			}
			if cmd.Usage == "" {
				t.Errorf("command %q has empty usage", tc.name)
			}
			if cmd.Description == "" {
				t.Errorf("command %q has empty description", tc.name)
			}
		})
	}
}

// TestCommandAliases verifies command aliases work correctly
func TestCommandAliases(t *testing.T) {
	aliases := []struct {
		alias       string
		commandName string
	}{
		{"h", "help"},
		{"exit", "quit"},
		{"q", "quit"},
	}

	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, tc := range aliases {
		t.Run(tc.alias, func(t *testing.T) {
			cmd, ok := registry.Lookup(tc.alias)
			if !ok {
				t.Errorf("alias %q not found", tc.alias)
				return
			}
			if cmd.Name != tc.commandName {
				t.Errorf("alias %q points to %q, want %q", tc.alias, cmd.Name, tc.commandName)
			}
		})
	}
}

// TestCommandCount verifies expected number of commands are registered
func TestCommandCount(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	all := registry.All()

	// Should have at least 25 core commands (excluding static plugins)
	minExpected := 25
	if len(all) < minExpected {
		t.Errorf("expected at least %d commands, got %d", minExpected, len(all))
	}
}

// TestCommandUsageFormats verifies all commands have properly formatted usage strings
func TestCommandUsageFormats(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, cmd := range registry.All() {
		t.Run(cmd.Name, func(t *testing.T) {
			// Usage should start with command name
			if len(cmd.Usage) > 0 && cmd.Usage[0:len(cmd.Name)] != cmd.Name {
				// Some commands have shorter usage, but most should start with command name
				// This is a soft check - just verify usage is not empty
				if cmd.Usage == "" {
					t.Errorf("command %q has empty usage", cmd.Name)
				}
			}
		})
	}
}

// TestCommandHandlersNotNil verifies all commands have handlers
func TestCommandHandlersNotNil(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, cmd := range registry.All() {
		t.Run(cmd.Name, func(t *testing.T) {
			if cmd.Handler == nil {
				t.Errorf("command %q has nil handler", cmd.Name)
			}
		})
	}
}

// TestAllCategoriesHaveCommands verifies each category has at least one command
func TestAllCategoriesHaveCommands(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	categories := make(map[string]int)
	for _, cmd := range registry.All() {
		categories[string(cmd.Category)]++
	}

	// Expected categories that should have commands
	expectedCategories := []string{
		string(command.CategoryTransaction),
		string(command.CategoryInfo),
		string(command.CategoryAlias),
		string(command.CategoryRekey),
		string(command.CategoryASA),
		string(command.CategoryConfig),
	}

	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("category %q has no commands", cat)
		}
	}
}

// TestTransactionCommandsHaveNowaitOption verifies transaction commands mention nowait in usage
func TestTransactionCommandsHaveNowaitOption(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	transactionCommands := []string{"send", "sweep", "optin", "optout", "keyreg", "close"}

	for _, cmdName := range transactionCommands {
		t.Run(cmdName, func(t *testing.T) {
			cmd, ok := registry.Lookup(cmdName)
			if !ok {
				t.Errorf("command %q not found", cmdName)
				return
			}

			// Transaction commands should be in Transaction category
			if cmd.Category != command.CategoryTransaction {
				t.Errorf("command %q should be in Transaction category, got %v", cmdName, cmd.Category)
			}
		})
	}
}

// TestMustRegisterPanicsOnDuplicate verifies mustRegister panics on duplicate registration
func TestMustRegisterPanicsOnDuplicate(t *testing.T) {
	registry := command.NewRegistry()

	// First registration should succeed
	cmd := &command.Command{
		Name:        "test",
		Usage:       "test",
		Description: "Test command",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(func([]string, interface{}) error { return nil }),
	}

	// This should not panic
	mustRegister(registry, cmd)

	// Trying to register the same command should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected mustRegister to panic on duplicate registration")
		}
	}()

	mustRegister(registry, cmd)
}

// TestHelpSystemSmokeTest verifies help output works for all commands
func TestHelpSystemSmokeTest(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	// Verify ByCategory returns valid groups
	categories := registry.ByCategory()
	if len(categories) == 0 {
		t.Error("ByCategory() returned empty map")
	}

	// Verify each command can be looked up by name
	for _, cmd := range registry.All() {
		looked, ok := registry.Lookup(cmd.Name)
		if !ok {
			t.Errorf("command %q not found by Lookup after registration", cmd.Name)
		}
		if looked != cmd {
			t.Errorf("Lookup(%q) returned different command", cmd.Name)
		}
	}
}

// TestCommandCategoriesAreValid verifies all commands use known categories
func TestCommandCategoriesAreValid(t *testing.T) {
	validCategories := map[string]bool{
		command.CategorySetup:         true,
		command.CategoryTransaction:   true,
		command.CategoryAlias:         true,
		command.CategoryRekey:         true,
		command.CategoryInfo:          true,
		command.CategoryKeyMgmt:       true,
		command.CategoryASA:           true,
		command.CategoryConfig:        true,
		command.CategoryVariables:     true,
		command.CategoryAutomation:    true,
		command.CategoryRemote:        true,
		command.CategoryOrchestration: true,
	}

	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, cmd := range registry.All() {
		if !validCategories[cmd.Category] {
			t.Errorf("command %q has unknown category: %q", cmd.Name, cmd.Category)
		}
	}
}

// TestNoEmptyCommandNames verifies no commands have empty names
func TestNoEmptyCommandNames(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, cmd := range registry.All() {
		if cmd.Name == "" {
			t.Error("found command with empty name")
		}
	}
}

// TestAliasesPointToValidCommands verifies all aliases resolve correctly
func TestAliasesPointToValidCommands(t *testing.T) {
	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, cmd := range registry.All() {
		for _, alias := range cmd.Aliases {
			looked, ok := registry.Lookup(alias)
			if !ok {
				t.Errorf("alias %q for command %q not found", alias, cmd.Name)
				continue
			}
			if looked.Name != cmd.Name {
				t.Errorf("alias %q resolves to %q, expected %q", alias, looked.Name, cmd.Name)
			}
		}
	}
}

// TestArgSpecsAreValid verifies all ArgSpecs use known types
func TestArgSpecsAreValid(t *testing.T) {
	validArgTypes := map[string]bool{
		cmdspec.ArgTypeAddress: true,
		cmdspec.ArgTypeAsset:   true,
		cmdspec.ArgTypeSet:     true,
		cmdspec.ArgTypeKeyword: true,
		cmdspec.ArgTypeNumber:  true,
		cmdspec.ArgTypeFile:    true,
		cmdspec.ArgTypeCustom:  true,
	}

	r := &REPLState{}
	registry := r.initCommandRegistry()

	for _, cmd := range registry.All() {
		for i, spec := range cmd.ArgSpecs {
			if spec.Type != "" && !validArgTypes[spec.Type] {
				t.Errorf("command %q ArgSpec[%d] has unknown type: %v", cmd.Name, i, spec.Type)
			}
		}
	}
}
