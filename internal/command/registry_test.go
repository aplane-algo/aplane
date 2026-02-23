// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

import (
	"testing"
)

// MockHandler implements Handler interface for testing
type MockHandler struct {
	executeFunc func(args []string, ctx *Context) error
}

func (h *MockHandler) Execute(args []string, ctx *Context) error {
	if h.executeFunc != nil {
		return h.executeFunc(args, ctx)
	}
	return nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry() returned nil")
	}
	if r.commands == nil {
		t.Error("NewRegistry() commands map is nil")
	}
	if r.primary == nil {
		t.Error("NewRegistry() primary slice is nil")
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	cmd := &Command{
		Name:        "test",
		Aliases:     []string{"t"},
		Usage:       "test [args]",
		Description: "Test command",
		Category:    CategoryInfo,
		Handler:     &MockHandler{},
	}

	err := r.Register(cmd)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify command is registered by name
	got, ok := r.Lookup("test")
	if !ok {
		t.Error("Register() command not found by name")
	}
	if got.Name != "test" {
		t.Errorf("Register() name = %v, want test", got.Name)
	}

	// Verify command is registered by alias
	got, ok = r.Lookup("t")
	if !ok {
		t.Error("Register() command not found by alias")
	}
	if got.Name != "test" {
		t.Errorf("Register() alias lookup name = %v, want test", got.Name)
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := NewRegistry()

	cmd1 := &Command{
		Name:    "test",
		Handler: &MockHandler{},
	}
	cmd2 := &Command{
		Name:    "test",
		Handler: &MockHandler{},
	}

	_ = r.Register(cmd1)
	err := r.Register(cmd2)
	if err == nil {
		t.Error("Register() expected error for duplicate command name")
	}
}

func TestRegistry_Register_AliasConflict(t *testing.T) {
	r := NewRegistry()

	cmd1 := &Command{
		Name:    "test",
		Aliases: []string{"t"},
		Handler: &MockHandler{},
	}
	cmd2 := &Command{
		Name:    "other",
		Aliases: []string{"t"}, // Conflicts with cmd1's alias
		Handler: &MockHandler{},
	}

	_ = r.Register(cmd1)
	err := r.Register(cmd2)
	if err == nil {
		t.Error("Register() expected error for conflicting alias")
	}
}

func TestRegistry_Lookup(t *testing.T) {
	r := NewRegistry()

	cmd := &Command{
		Name:    "test",
		Aliases: []string{"t", "tst"},
		Handler: &MockHandler{},
	}
	_ = r.Register(cmd)

	tests := []struct {
		name    string
		lookup  string
		wantOK  bool
		wantCmd string
	}{
		{"by name", "test", true, "test"},
		{"by alias t", "t", true, "test"},
		{"by alias tst", "tst", true, "test"},
		{"not found", "notexist", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := r.Lookup(tt.lookup)
			if ok != tt.wantOK {
				t.Errorf("Lookup() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got.Name != tt.wantCmd {
				t.Errorf("Lookup() name = %v, want %v", got.Name, tt.wantCmd)
			}
		})
	}
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()

	cmd1 := &Command{Name: "alpha", Handler: &MockHandler{}}
	cmd2 := &Command{Name: "beta", Handler: &MockHandler{}}
	cmd3 := &Command{Name: "gamma", Handler: &MockHandler{}}

	_ = r.Register(cmd1)
	_ = r.Register(cmd2)
	_ = r.Register(cmd3)

	all := r.All()
	if len(all) != 3 {
		t.Errorf("All() count = %v, want 3", len(all))
	}
}

func TestRegistry_ByCategory(t *testing.T) {
	r := NewRegistry()

	cmd1 := &Command{Name: "send", Category: CategoryTransaction, Handler: &MockHandler{}}
	cmd2 := &Command{Name: "balance", Category: CategoryInfo, Handler: &MockHandler{}}
	cmd3 := &Command{Name: "status", Category: CategoryInfo, Handler: &MockHandler{}}

	_ = r.Register(cmd1)
	_ = r.Register(cmd2)
	_ = r.Register(cmd3)

	categories := r.ByCategory()

	if len(categories[CategoryTransaction]) != 1 {
		t.Errorf("ByCategory() Transaction count = %v, want 1", len(categories[CategoryTransaction]))
	}
	if len(categories[CategoryInfo]) != 2 {
		t.Errorf("ByCategory() Info count = %v, want 2", len(categories[CategoryInfo]))
	}

	// Verify sorting within category
	infoCmds := categories[CategoryInfo]
	if len(infoCmds) >= 2 && infoCmds[0].Name > infoCmds[1].Name {
		t.Error("ByCategory() commands should be sorted alphabetically within category")
	}
}
