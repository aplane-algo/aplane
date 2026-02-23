// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name     string
		manifest Manifest
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid minimal manifest",
			manifest: Manifest{
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "A test plugin",
				Executable:  "test-plugin",
				Commands: []Command{
					{Name: "test", Description: "Test command"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid full manifest",
			manifest: Manifest{
				Name:            "test-plugin",
				Version:         "1.0.0",
				Description:     "A test plugin",
				Author:          "Test Author",
				Homepage:        "https://example.com",
				Executable:      "test-plugin",
				Args:            []string{"--mode", "production"},
				Commands:        []Command{{Name: "cmd1", Description: "Command 1"}},
				Networks:        []string{"testnet", "mainnet"},
				Timeout:         60,
				ProtocolVersion: "1.0",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			manifest: Manifest{
				Version:     "1.0.0",
				Description: "A test plugin",
				Executable:  "test-plugin",
				Commands:    []Command{{Name: "test", Description: "Test"}},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "missing version",
			manifest: Manifest{
				Name:        "test-plugin",
				Description: "A test plugin",
				Executable:  "test-plugin",
				Commands:    []Command{{Name: "test", Description: "Test"}},
			},
			wantErr: true,
			errMsg:  "version is required",
		},
		{
			name: "missing description",
			manifest: Manifest{
				Name:       "test-plugin",
				Version:    "1.0.0",
				Executable: "test-plugin",
				Commands:   []Command{{Name: "test", Description: "Test"}},
			},
			wantErr: true,
			errMsg:  "description is required",
		},
		{
			name: "missing executable",
			manifest: Manifest{
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "A test plugin",
				Commands:    []Command{{Name: "test", Description: "Test"}},
			},
			wantErr: true,
			errMsg:  "executable is required",
		},
		{
			name: "no commands",
			manifest: Manifest{
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "A test plugin",
				Executable:  "test-plugin",
				Commands:    []Command{},
			},
			wantErr: true,
			errMsg:  "at least one command is required",
		},
		{
			name: "command missing name",
			manifest: Manifest{
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "A test plugin",
				Executable:  "test-plugin",
				Commands:    []Command{{Name: "", Description: "Test"}},
			},
			wantErr: true,
			errMsg:  "command[0]: name is required",
		},
		{
			name: "command missing description",
			manifest: Manifest{
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "A test plugin",
				Executable:  "test-plugin",
				Commands:    []Command{{Name: "test", Description: ""}},
			},
			wantErr: true,
			errMsg:  "command[0]: description is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.manifest.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestManifestValidateDefaults(t *testing.T) {
	m := Manifest{
		Name:        "test-plugin",
		Version:     "1.0.0",
		Description: "A test plugin",
		Executable:  "test-plugin",
		Commands:    []Command{{Name: "test", Description: "Test"}},
		// No Timeout or ProtocolVersion set
	}

	err := m.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check defaults were applied
	if m.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30 (default)", m.Timeout)
	}
	if m.ProtocolVersion != "1.0" {
		t.Errorf("ProtocolVersion = %q, want %q (default)", m.ProtocolVersion, "1.0")
	}
}

func TestManifestSupportsNetwork(t *testing.T) {
	tests := []struct {
		name     string
		networks []string
		query    string
		want     bool
	}{
		{
			name:     "no restriction supports all",
			networks: nil,
			query:    "testnet",
			want:     true,
		},
		{
			name:     "empty networks supports all",
			networks: []string{},
			query:    "mainnet",
			want:     true,
		},
		{
			name:     "explicit support",
			networks: []string{"testnet", "mainnet"},
			query:    "testnet",
			want:     true,
		},
		{
			name:     "not supported",
			networks: []string{"testnet"},
			query:    "mainnet",
			want:     false,
		},
		{
			name:     "betanet not in list",
			networks: []string{"testnet", "mainnet"},
			query:    "betanet",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manifest{Networks: tt.networks}
			if got := m.SupportsNetwork(tt.query); got != tt.want {
				t.Errorf("SupportsNetwork(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

func TestManifestFindCommand(t *testing.T) {
	m := &Manifest{
		Commands: []Command{
			{Name: "cmd1", Description: "Command 1"},
			{Name: "cmd2", Description: "Command 2"},
			{Name: "cmd3", Description: "Command 3"},
		},
	}

	tests := []struct {
		name      string
		cmdName   string
		wantFound bool
		wantDesc  string
	}{
		{"find first", "cmd1", true, "Command 1"},
		{"find middle", "cmd2", true, "Command 2"},
		{"find last", "cmd3", true, "Command 3"},
		{"not found", "cmd4", false, ""},
		{"empty name", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := m.FindCommand(tt.cmdName)

			if tt.wantFound {
				if cmd == nil {
					t.Error("expected to find command but got nil")
					return
				}
				if cmd.Description != tt.wantDesc {
					t.Errorf("Description = %q, want %q", cmd.Description, tt.wantDesc)
				}
			} else {
				if cmd != nil {
					t.Errorf("expected nil but got command: %+v", cmd)
				}
			}
		})
	}
}

func TestManifestGetExecutablePath(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()

	// Create a fake executable in the temp dir
	localExec := filepath.Join(tmpDir, "local-plugin")
	if err := os.WriteFile(localExec, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatalf("failed to create test executable: %v", err)
	}

	tests := []struct {
		name       string
		executable string
		pluginDir  string
		wantPath   string
		checkExact bool
	}{
		{
			name:       "absolute path unchanged",
			executable: "/usr/bin/test",
			pluginDir:  tmpDir,
			wantPath:   "/usr/bin/test",
			checkExact: true,
		},
		{
			name:       "relative path found locally",
			executable: "local-plugin",
			pluginDir:  tmpDir,
			wantPath:   localExec,
			checkExact: true,
		},
		{
			name:       "relative path not found falls back to local",
			executable: "nonexistent-plugin",
			pluginDir:  tmpDir,
			wantPath:   filepath.Join(tmpDir, "nonexistent-plugin"),
			checkExact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manifest{Executable: tt.executable}
			got := m.GetExecutablePath(tt.pluginDir)

			if tt.checkExact && got != tt.wantPath {
				t.Errorf("GetExecutablePath() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		wantErr  bool
		errMsg   string
		validate func(*testing.T, *Manifest)
	}{
		{
			name: "valid manifest",
			content: `{
				"name": "test-plugin",
				"version": "1.0.0",
				"description": "A test plugin",
				"executable": "test-plugin",
				"commands": [{"name": "test", "description": "Test command"}]
			}`,
			wantErr: false,
			validate: func(t *testing.T, m *Manifest) {
				if m.Name != "test-plugin" {
					t.Errorf("Name = %q, want %q", m.Name, "test-plugin")
				}
				if len(m.Commands) != 1 {
					t.Errorf("len(Commands) = %d, want 1", len(m.Commands))
				}
			},
		},
		{
			name: "manifest with functions",
			content: `{
				"name": "defi-plugin",
				"version": "2.0.0",
				"description": "DeFi plugin",
				"executable": "defi",
				"commands": [{"name": "swap", "description": "Swap tokens"}],
				"functions": [
					{
						"name": "getPrice",
						"description": "Get token price",
						"params": [{"name": "token", "type": "string"}],
						"returns": "number",
						"command": ["price", "$token"]
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, m *Manifest) {
				if len(m.Functions) != 1 {
					t.Errorf("len(Functions) = %d, want 1", len(m.Functions))
					return
				}
				if m.Functions[0].Name != "getPrice" {
					t.Errorf("Functions[0].Name = %q, want %q", m.Functions[0].Name, "getPrice")
				}
			},
		},
		{
			name:    "invalid json",
			content: `{invalid json`,
			wantErr: true,
			errMsg:  "failed to parse manifest",
		},
		{
			name: "missing required field",
			content: `{
				"version": "1.0.0",
				"description": "No name",
				"executable": "test",
				"commands": [{"name": "test", "description": "Test"}]
			}`,
			wantErr: true,
			errMsg:  "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write manifest file
			manifestPath := filepath.Join(tmpDir, tt.name+".json")
			if err := os.WriteFile(manifestPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write test manifest: %v", err)
			}

			m, err := load(manifestPath)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.validate != nil {
				tt.validate(t, m)
			}
		})
	}
}

func TestLoadNonexistent(t *testing.T) {
	_, err := load("/nonexistent/path/manifest.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "failed to read manifest") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadFromDir(t *testing.T) {
	// Create temp directory with manifest
	tmpDir := t.TempDir()
	manifestContent := `{
		"name": "dir-plugin",
		"version": "1.0.0",
		"description": "Plugin loaded from directory",
		"executable": "plugin",
		"commands": [{"name": "test", "description": "Test"}]
	}`

	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	m, err := LoadFromDir(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Name != "dir-plugin" {
		t.Errorf("Name = %q, want %q", m.Name, "dir-plugin")
	}
}

func TestCommandFields(t *testing.T) {
	// Test that all command fields are preserved
	m := &Manifest{
		Name:        "test",
		Version:     "1.0",
		Description: "Test",
		Executable:  "test",
		Commands: []Command{
			{
				Name:        "complex-cmd",
				Description: "A complex command",
				Usage:       "complex-cmd <arg1> [arg2]",
				Examples:    []string{"complex-cmd foo", "complex-cmd foo bar"},
				Returns:     "{ txid: string }",
				Category:    "utility",
			},
		},
	}

	if err := m.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	cmd := m.FindCommand("complex-cmd")
	if cmd == nil {
		t.Fatal("command not found")
	}

	if cmd.Usage != "complex-cmd <arg1> [arg2]" {
		t.Errorf("Usage = %q, want %q", cmd.Usage, "complex-cmd <arg1> [arg2]")
	}
	if len(cmd.Examples) != 2 {
		t.Errorf("len(Examples) = %d, want 2", len(cmd.Examples))
	}
	if cmd.Returns != "{ txid: string }" {
		t.Errorf("Returns = %q, want %q", cmd.Returns, "{ txid: string }")
	}
	if cmd.Category != "utility" {
		t.Errorf("Category = %q, want %q", cmd.Category, "utility")
	}
}

func TestFunctionFields(t *testing.T) {
	// Test that function fields are preserved through JSON round-trip
	content := `{
		"name": "typed-plugin",
		"version": "1.0.0",
		"description": "Plugin with typed functions",
		"executable": "typed",
		"commands": [{"name": "base", "description": "Base command"}],
		"functions": [
			{
				"name": "transfer",
				"description": "Transfer tokens",
				"params": [
					{"name": "from", "type": "address", "description": "Sender address"},
					{"name": "to", "type": "address", "description": "Receiver address"},
					{"name": "amount", "type": "number", "description": "Amount to transfer"}
				],
				"returns": "{ txid: string, confirmed: boolean }",
				"command": ["transfer", "$from", "$to", "$amount"]
			}
		]
	}`

	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	m, err := load(manifestPath)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(m.Functions) != 1 {
		t.Fatalf("len(Functions) = %d, want 1", len(m.Functions))
	}

	fn := m.Functions[0]
	if fn.Name != "transfer" {
		t.Errorf("Name = %q, want %q", fn.Name, "transfer")
	}
	if len(fn.Params) != 3 {
		t.Errorf("len(Params) = %d, want 3", len(fn.Params))
	}
	if fn.Params[0].Type != "address" {
		t.Errorf("Params[0].Type = %q, want %q", fn.Params[0].Type, "address")
	}
	if len(fn.Command) != 4 {
		t.Errorf("len(Command) = %d, want 4", len(fn.Command))
	}
}
