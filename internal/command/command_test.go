// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

import (
	"testing"
)

func TestCommand_Struct(t *testing.T) {
	cmd := &Command{
		Name:        "test",
		Aliases:     []string{"t", "tst"},
		Usage:       "test <arg>",
		Description: "Test command description",
		LongHelp:    "Detailed help for test command",
		Category:    CategoryInfo,
		IsPlugin:    false,
		Handler:     &MockHandler{},
	}

	if cmd.Name != "test" {
		t.Errorf("Command.Name = %v, want test", cmd.Name)
	}
	if len(cmd.Aliases) != 2 {
		t.Errorf("Command.Aliases count = %v, want 2", len(cmd.Aliases))
	}
	if cmd.Usage != "test <arg>" {
		t.Errorf("Command.Usage = %v, want 'test <arg>'", cmd.Usage)
	}
	if cmd.Description != "Test command description" {
		t.Errorf("Command.Description = %v, want 'Test command description'", cmd.Description)
	}
	if cmd.LongHelp != "Detailed help for test command" {
		t.Errorf("Command.LongHelp = %v", cmd.LongHelp)
	}
	if cmd.Category != CategoryInfo {
		t.Errorf("Command.Category = %v, want %v", cmd.Category, CategoryInfo)
	}
	if cmd.IsPlugin {
		t.Error("Command.IsPlugin should be false")
	}
	if cmd.Handler == nil {
		t.Error("Command.Handler should not be nil")
	}
}

func TestCategories(t *testing.T) {
	// Verify category constants are defined
	categories := []string{
		CategorySetup,
		CategoryTransaction,
		CategoryAlias,
		CategoryRekey,
		CategoryInfo,
		CategoryKeyMgmt,
		CategoryASA,
		CategoryConfig,
		CategoryVariables,
		CategoryAutomation,
		CategoryRemote,
		CategoryOrchestration,
	}

	for _, cat := range categories {
		if cat == "" {
			t.Error("Category constant should not be empty")
		}
	}
}

func TestHandler_Execute(t *testing.T) {
	executed := false
	handler := &MockHandler{
		executeFunc: func(args []string, ctx *Context) error {
			executed = true
			if len(args) != 2 {
				t.Errorf("Execute() args count = %v, want 2", len(args))
			}
			if args[0] != "arg1" {
				t.Errorf("Execute() args[0] = %v, want arg1", args[0])
			}
			return nil
		},
	}

	ctx := &Context{Network: "testnet"}
	err := handler.Execute([]string{"arg1", "arg2"}, ctx)
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if !executed {
		t.Error("Execute() should have been called")
	}
}

func TestHandler_Execute_NilFunc(t *testing.T) {
	handler := &MockHandler{} // executeFunc is nil
	err := handler.Execute([]string{}, &Context{})
	if err != nil {
		t.Errorf("Execute() with nil func should return nil, got %v", err)
	}
}
