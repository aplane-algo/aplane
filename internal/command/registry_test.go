// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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
		return
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

func TestRegistry_Register_AliasConflictIsAtomic(t *testing.T) {
	r := NewRegistry()

	cmd1 := &Command{
		Name:    "existing",
		Aliases: []string{"taken"},
		Handler: &MockHandler{},
	}
	cmd2 := &Command{
		Name:    "partial",
		Aliases: []string{"ok", "taken", "later"},
		Handler: &MockHandler{},
	}

	if err := r.Register(cmd1); err != nil {
		t.Fatalf("Register(cmd1) error = %v", err)
	}
	err := r.Register(cmd2)
	if err == nil {
		t.Fatal("Register(cmd2) expected error for conflicting alias")
	}

	if _, ok := r.Lookup("partial"); ok {
		t.Fatal("failed registration should not leave primary command registered")
	}
	if _, ok := r.Lookup("ok"); ok {
		t.Fatal("failed registration should not leave earlier aliases registered")
	}
	if _, ok := r.Lookup("later"); ok {
		t.Fatal("failed registration should not leave later aliases registered")
	}

	all := r.All()
	if len(all) != 1 || all[0].Name != "existing" {
		t.Fatalf("All() = %#v, want only existing command", all)
	}
}

func TestRegistry_Register_ValidatesCommandInput(t *testing.T) {
	tests := []struct {
		name    string
		cmd     *Command
		wantErr string
	}{
		{name: "nil command", cmd: nil, wantErr: "command is nil"},
		{name: "empty name", cmd: &Command{Name: "", Handler: &MockHandler{}}, wantErr: "command name is required"},
		{name: "nil handler", cmd: &Command{Name: "test"}, wantErr: `command "test" handler is required`},
		{name: "empty alias", cmd: &Command{Name: "test", Aliases: []string{""}, Handler: &MockHandler{}}, wantErr: `command "test" has empty alias`},
		{name: "duplicate alias", cmd: &Command{Name: "test", Aliases: []string{"a", "a"}, Handler: &MockHandler{}}, wantErr: `command "test" has duplicate alias "a"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			err := r.Register(tt.cmd)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
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
